require "xxhash"
require "openssl/x509/spki"

module Pwnedkeys
  class Filter

    # Base class for all Pwnedkeys::Filter exceptions
    class Error < StandardError; end

    # Raised when a data file appears to not be a valid data file.
    class InvalidFileError < Error; end

    # Raised when the key to be searched for isn't a key
    class InvalidKeyError < Error; end

    # Attempt was made to query or modify a closed filter
    class FilterClosedError < Error; end

    class Header
      attr_reader :signature, :revision, :update_time, :entry_count, :hash_count, :hash_length

      def self.from_fd(fd)
        fd.seek(0)
        case fd.read(6)
        when "pkbfv1"
          V1Header.from_fd(fd)
        else
          raise InvalidFileError,
                "No recognised file signature found"
        end
      end

      def initialize(**params)
        @revision    = 0
        @update_time = Time.at(0)
        @entry_count = 0

        params.each do |k, v|
          instance_variable_set(:"@#{k}", v)
        end
      end

      def header_size
        to_s.length
      end

      def update!
        @revision += 1
      end

      def entry_added!
        @update_time = Time.now
        @entry_count += 1
      end
    end
    private_constant :Header

    class V1Header < Header
      def self.from_fd(fd)
        fd.seek(0)
        signature, revision, update, entry_count, hash_count, hash_length = fd.read(24).unpack("a6L>Q>L>CC")
        update_time = Time.at(update)

        self.new(
          signature:   signature,
          revision:    revision,
          update_time: update_time,
          entry_count: entry_count,
          hash_count:  hash_count,
          hash_length: hash_length
        )
      end

      def initialize(**params)
        @signature = "pkbfv1"

        super
      end

      def to_s
        [@signature, @revision, @update_time.to_i, @entry_count, @hash_count, @hash_length].pack("a*L>Q>L>CC")
      end
    end
    private_constant :V1Header

    # Create a new filter data file.
    #
    # Initialize a file, which cannot already exist, to be a pwnedkeys bloom filter
    # v1 file.  The file is not opened for use, it is simply created on the filesystem
    # at the location specified.
    #
    # @param filename [String] the file to be created.  It can be an absolute or relative
    #    path, or anything else that `File.open` will accept.
    #
    # @param hash_count [Integer] how many filter bits each element in the bloom filter will
    #    set.
    #
    # @param hash_length [Integer] the number of bits that will be used for each hash value.
    #
    # @raise [SystemCallError] if any sort of filesystem-related problem occurs, an
    #    `Errno`-related exception will be raised.  Likely candidates include `EEXIST`
    #    (the file you specified already exists), `ENOENT` (the directory you specified
    #    doesn't exist), and `EPERM` (you don't have permissions to create a file where
    #    you want it).
    #
    # @return [void]
    #
    def self.create(filename, hash_count:, hash_length:)
      File.open(filename, File::WRONLY | File::CREAT | File::EXCL) do |fd|
        header = V1Header.new(hash_count: hash_count, hash_length: hash_length)

        fd.write(header.to_s)
        fd.seek((2 ** hash_length) / 8 - 1, :CUR)
        fd.write("\0")
      end

      nil
    end

    # Calculate count/length parameters for a given entry count and desired false-positive rate.
    #
    # @param entries [Integer] how many elements the bloom filter should
    #    accommodate.
    #
    # @param fp_rate [Float] the maximum false-positive rate you wish to
    #    accept.
    #
    # @return [Hash<Symbol, Integer>] the `:hash_count` and `:hash_length` which
    #    will produce the desired false-positive rate if the filter is filled
    #    with the specified number of entries.
    #
    def self.filter_parameters(entries:, fp_rate:)
      # Blessings unto https://en.wikipedia.org/wiki/Bloom_filter#Optimal_number_of_hash_functions
      optimal_filter_bits = (-1 * entries * Math.log(fp_rate) / Math.log(2) / Math.log(2))
      hash_length = (Math.log2(optimal_filter_bits)).ceil
      actual_filter_bits = 2 ** hash_length

      # We could, in theory, just use the "optimal k" (hash count), which would
      # often produce an actual false-positive rate much smaller than our
      # target (because actual_filter_bits can be *significantly* larger than
      # optimal_filter_bits).  Instead, to minimise the hashing required, we
      # can use the extra filter length available to choose a smaller k that
      # still satisfies the target false positive rate.
      #
      # Because my algebra isn't up to solving the FP rate equation for k, and
      # because the search space of possible values of k is small and bounded
      # (by 1, and by the "optimal k" on the upper bound), brute-forcing things
      # seems the easiest option.

      upper_bound = (Math.log(2) * actual_filter_bits / entries).ceil
      hash_count = (1..upper_bound).find do |k|
        (1 - (1 - 1.0 / actual_filter_bits) ** (k * entries)) ** k < fp_rate
      end

      if hash_count.nil?
        #:nocov:
        raise RuntimeError, "CAN'T HAPPEN: Could not determine hash_count for entries: #{entries}, fp_rate: #{fp_rate}.  Please report a violation of the laws of mathematics."
        #:nocov:
      end

      {
        hash_count:  hash_count,
        hash_length: hash_length,
      }
    end

    # Open an existing pwnedkeys bloom filter data file.
    #
    # @param filename [String] the file to open.
    #
    # @raise [SystemCallError] if anything low-level goes wrong, you will get some
    #    sort of `Errno`-related exception raised, such as `ENOENT` (the file you
    #    specified does not exist) or `EPERM` (you don't have access to the file
    #    specified).
    #
    # @raise [Pwnedkeys::Filter::InvalidFileError] if the specified file exists,
    #    but is not recognised as a valid pwnedkeys filter file.
    #
    # @return [Pwnedkeys::Filter]
    #
    def self.open(filename)
      filter = Pwnedkeys::Filter.new(filename)

      if block_given?
        begin
          yield filter
        ensure
          filter.close
        end
      else
        filter
      end
    end

    # Create a new Pwnedkeys::Filter.
    #
    # Equivalent to {.open}, without the possibility of block-style access.
    #
    # @see .open
    #
    def initialize(filename)
      @fd     = File.open(filename, File::RDWR, binmode: true)
      @header = Header.from_fd(@fd)
    end

    # Query the bloom filter.
    #
    # @param key [OpenSSL::PKey::PKey, OpenSSL::X509::SPKI, String] the key
    #    to query the filter for.
    #
    # @return [Boolean] whether the queried key *probably* exists in the
    #    filter (`true`), or whether it *definitely doesn't* (`false`).
    #
    # @raise [Pwnedkeys::Filter::InvalidKeyError] if the object passed in
    #    isn't recognised as a key.
    #
    # @raise [Pwnedkeys::Filter::FilterClosedError] if you try to query
    #    a filter object which has had {#close} called on it.
    #
    def probably_includes?(key)
      raise FilterClosedError if @fd.nil?

      spki = spkify(key)
      filter_bits(spki.to_der).all?
    end

    # Add a new key (or SPKI) to the filter.
    #
    # @param key [OpenSSL::PKey::PKey, OpenSSL::X509::SPKI, String] the key
    #    to add to the filter.
    #
    # @return [Boolean] whether the key was added as a new entry.  Due to the
    #    probabilistic nature of the bloom filter structure, it is possible to
    #    add two completely different keys and yet it looks like the "same"
    #    key to the bloom filter.  Adding two colliding keys isn't a fatal
    #    error, but it is a hint that perhaps the existing filter is getting
    #    a little too full.
    #
    # @raise [Pwnedkeys::Filter::FilterClosedError] if you try to add a key
    #    to a filter object which has had {#close} called on it.
    #
    def add(key)
      raise FilterClosedError if @fd.nil?

      return false if probably_includes?(key)

      spki = spkify(key)

      begin
        @fd.flock(File::LOCK_EX)
        filter_positions(spki.to_der).each do |n|
          @fd.seek(n / 8 + @header.header_size, :SET)
          byte = @fd.read(1).ord
          @fd.seek(-1, :CUR)

          mask = 2 ** (7 - (n % 8))
          new_byte = byte | mask

          @fd.write(new_byte.chr)
        end

        @header.entry_added!

        # Only update the revision if this is the first add in this filter,
        # because otherwise the revision counter would just be the same as the
        # entry counter, and that would be pointless.
        unless @already_modified
          @header.update!
        end

        @fd.seek(0)
        @fd.write(@header.to_s)
        @fd.fdatasync
      ensure
        @fd.flock(File::LOCK_UN)
      end

      @already_modified = true
    end

    # Signal that the filter should be closed for further querying and manipulation.
    #
    # @return [void]
    #
    # @raise [SystemCallError] if something filesystem-ish fails.
    #
    def close
      @fd.close
      @fd = nil
    end

    # An estimate of the false-positive rate inherent in the filter.
    #
    # Given the parameters of the filter, we can estimate roughly what the
    # false-positive rate will be when querying this filter.
    #
    # @return [Float] the approximate probability of a query result being a
    #    false positive, expressed as a floating-point number between 0 and 1.
    #
    def false_positive_rate
      # Taken wholesale from https://en.wikipedia.org/wiki/Bloom_filter#Probability_of_false_positives
      (1 - (1 - 1.0 / filter_bit_count) ** (hash_count * entry_count)) ** hash_count
    end

    private

    def hash_count
      @header.hash_count
    end

    def hash_length
      @header.hash_length
    end

    def entry_count
      @header.entry_count
    end

    def filter_bit_count
      @filter_size ||= (2 ** hash_length)
    end

    def spkify(key)
      if key.is_a?(OpenSSL::X509::SPKI)
        key
      elsif key.is_a?(OpenSSL::PKey::PKey)
        key.to_spki
      elsif key.is_a?(String)
        begin
          OpenSSL::PKey.read(key).to_spki
        rescue OpenSSL::ASN1::ASN1Error, OpenSSL::PKey::PKeyError
          begin
            OpenSSL::X509::SPKI.new(key)
          rescue OpenSSL::ASN1::ASN1Error, OpenSSL::X509::SPKIError
            raise InvalidKeyError,
                  "Could not parse provided key as a key or SPKI structure"
          end
        end
      else
        raise InvalidKeyError,
              "Did not recognise the provided key"
      end
    end

    def filter_bits(s)
      begin
        @fd.flock(File::LOCK_SH)
        filter_positions(s).map do |n|
          @fd.seek(n / 8 + @header.header_size, :SET)
          byte = @fd.read(1).ord
          mask = 2 ** (7 - (n % 8))

          (byte & mask) > 0
        end
      ensure
        @fd.flock(File::LOCK_UN)
      end
    end

    def filter_positions(s)
      h1 = XXhash.xxh64(s, 0)
      h2 = XXhash.xxh64(s, 1)
      h2 += 1 if h2 % 2 == 0

      (0..hash_count-1).map do |i|
        (h1 + i * h2 + (i ** 3 - i) / 6) % filter_bit_count
      end
    end
  end
end
