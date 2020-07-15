require_relative "../spec_helper"
require "openssl"

require "pwnedkeys/filter"

describe Pwnedkeys::Filter do
  let(:datafile) { nil }

  before(:each) do
    if datafile
      File.open(testfile, "w") { |fd| fd.write(File.read(File.expand_path("../../fixtures/#{datafile}.pkbf", __FILE__))); fd.close }
    end
  end

  let(:testfile) { "#{Dir.tmpdir}/pwnedkeys-filter-spec_#{$$}.#{rand(1000000)}" }
  let(:filter) { Pwnedkeys::Filter.open(testfile) }

  after(:each) do
    File.unlink(testfile) rescue nil
  end

  describe ".create" do
    it "needs a filename, hash count, and length" do
      expect { described_class.create(testfile, hash_count: 4, hash_length: 8) }.to_not raise_error
    end

    it "writes out a new filter file" do
      described_class.create(testfile, hash_count: 2, hash_length: 4)

      expect(File.exists?(testfile)).to be(true)
    end

    context "the filter file" do
      let(:data) { File.read(testfile) }

      before(:each) do
        described_class.create(testfile, hash_count: 5, hash_length: 7)
      end

      it "has the right file signature" do
        expect(data[0..5]).to eq("\x70\x6B\x62\x66\x76\x31")
      end

      it "has a revision counter of zero" do
        expect(data[6..9]).to eq("\0\0\0\0")
      end

      it "has an update time of a looooong time ago" do
        expect(data[10..17]).to eq("\0\0\0\0\0\0\0\0")
      end

      it "has no entries" do
        expect(data[18..21]).to eq("\0\0\0\0")
      end

      it "has the specified hash count" do
        expect(data[22]).to eq("\x05")
      end

      it "has the specified hash length" do
        expect(data[23]).to eq("\x07")
      end

      it "is the correct length" do
        expect(data.length).to eq((2 ** 7) / 8 + 24)
      end
    end

    context "when the file already exists" do
      it "raises an exception" do
        File.open(testfile, "w").close

        expect { described_class.create(testfile, hash_count: 1, hash_length: 1) }.to raise_error(Errno::EEXIST)
      end
    end
  end

  describe ".filter_parameters" do
    it "returns expected results" do
      expect(Pwnedkeys::Filter.filter_parameters(entries: 42, fp_rate: 0.1)).to eq(hash_count: 2, hash_length: 8)
      expect(Pwnedkeys::Filter.filter_parameters(entries: 1000, fp_rate: 0.01)).to eq(hash_count: 3, hash_length: 14)
      expect(Pwnedkeys::Filter.filter_parameters(entries: 1_200_000, fp_rate: 0.01)).to eq(hash_count: 3, hash_length: 24)
    end
  end

  describe ".open" do
    context "with an existent and ordinary data file" do
      let(:datafile) { "2_4_1" }

      it "returns a Pwnedkeys::Filter" do
        expect(described_class.open(testfile)).to be_a(described_class)
      end
    end

    context "in block mode" do
      let(:datafile) { "2_4_1" }

      it "yields a Pwnedkeys::Filter" do
        described_class.open(testfile) do |filter|
          expect(filter).to be_a(described_class)
        end
      end

      it "returns the last value of the block" do
        expect(described_class.open(testfile) { 42 }).to eq(42)
      end
    end

    context "with a corrupt file" do
      before(:each) do
        File.open(testfile, "w") { |fd| fd.write("lolcats!"); fd.close }
      end

      it "raises an exception" do
        expect { described_class.open(testfile) }.to raise_error(Pwnedkeys::Filter::InvalidFileError)
      end
    end
  end

  describe "#probably_includes?" do
    let(:included_key) do
      # This is a *32-bit* RSA key.  Probably not particularly secure.
      OpenSSL::PKey.read("MC4CAQACBQDKmgsJAgMBAAECBQCkTLh1AgMA90MCAwDRwwIDANB/AgIuqwIDAINV".unpack("m").first)
    end

    let(:good_key) do
      # At the size of filter file we're using, there's a reasonably good chance that
      # a randomly-generated key would sometimes be seen as "present", so we want
      # to have a key we *know* doesn't match.
      OpenSSL::PKey.read("MC4CAQACBQDRx49xAgMBAAECBHmminkCAwDpYwIDAOYbAgMAhZkCAwChowIDAL3E".unpack("m").first)
    end

    let(:datafile) { "2_4_1" }

    it "says true for our included test key" do
      expect(filter.probably_includes?(included_key)).to be(true)
    end

    it "says false for our good key" do
      expect(filter.probably_includes?(good_key)).to be(false)
    end

    it "accepts the key as an SPKI" do
      expect(filter.probably_includes?(included_key.to_spki)).to be(true)
    end

    it "accepts the key as a DER string" do
      expect(filter.probably_includes?(included_key.to_der)).to be(true)
    end

    it "accepts the key as a DER string of the SPKI" do
      expect(filter.probably_includes?(included_key.to_spki.to_der)).to be(true)
    end

    it "raises an error if the string is unparseable" do
      expect { filter.probably_includes?("yo mama") }.to raise_error(Pwnedkeys::Filter::InvalidKeyError)
    end

    it "raises an error if the key is a rando data type" do
      expect { filter.probably_includes?(%w{yo mama}) }.to raise_error(Pwnedkeys::Filter::InvalidKeyError)
    end
  end

  describe "#add" do
    let(:key1) do
      OpenSSL::PKey.read("MC4CAQACBQDKmgsJAgMBAAECBQCkTLh1AgMA90MCAwDRwwIDANB/AgIuqwIDAINV".unpack("m").first)
    end

    let(:key2) do
      OpenSSL::PKey.read("MC4CAQACBQDRx49xAgMBAAECBHmminkCAwDpYwIDAOYbAgMAhZkCAwChowIDAL3E".unpack("m").first)
    end

    let(:filter) { Pwnedkeys::Filter.create(testfile, hash_count: 2, hash_length: 4); Pwnedkeys::Filter.open(testfile) }

    context "adding one key" do
      before(:each) do
        filter.add(key1)
        filter.close
      end

      it "adds the key we've given" do
        expect(File.read(testfile, nil, 24)).to eq("\x02\x01")
      end

      it "returns false if the key is added multiple times" do
        filter_redux = Pwnedkeys::Filter.open(testfile)
        expect(filter_redux.add(key1)).to eq(false)
      end

      it "updates the filter metadata" do
        # Revision
        expect(File.read(testfile, 4, 6)).to eq("\x00\x00\x00\x01")
        # Update time
        expect(File.read(testfile, 8, 10).unpack("Q>").first).to be_within(1).of(Time.now.to_i)
        # Entry count
        expect(File.read(testfile, 4, 18)).to eq("\x00\x00\x00\x01")
      end
    end

    context "adding multiple keys" do
      before(:each) do
        filter.add(key1)
        filter.add(key2)
        filter.close
      end

      it "sets the bits for both keys we've given" do
        expect(File.read(testfile, nil, 24)).to eq("\x02\x61")
      end

      it "returns false if either key is added again" do
        filter_redux = Pwnedkeys::Filter.open(testfile)
        expect(filter_redux.add(key1)).to eq(false)
        expect(filter_redux.add(key2)).to eq(false)
      end

      it "updates the filter metadata" do
        # Revision
        expect(File.read(testfile, 4, 6)).to eq("\x00\x00\x00\x01")
        # Update time
        expect(File.read(testfile, 8, 10).unpack("Q>").first).to be_within(1).of(Time.now.to_i)
        # Entry count
        expect(File.read(testfile, 4, 18)).to eq("\x00\x00\x00\x02")
      end
    end
  end

  describe "#false_positive_rate" do
    let(:datafile) { "2_4_1" }

    it "calculates the correct false-positive rate" do
      expect(filter.false_positive_rate).to be_within(0.001).of(0.01466)
    end
  end

  describe "#sync" do
    it "forces a sync to disk" do
      Pwnedkeys::Filter.create(testfile, hash_count: 2, hash_length: 4)
      expect(filter.instance_variable_get(:@fd)).to receive(:fdatasync)

      filter.sync
    end
  end
end
