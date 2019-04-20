This is a gem for creating and querying [pwnedkeys.com](https://pwnedkeys.com)
[bloom filters](https://pwnedkeys.com/filter.html).


# Installation

It's a gem:

    gem install pwnedkeys-filter

There's also the wonders of [the Gemfile](http://bundler.io):

    gem 'pwnedkeys-filter'

If you're the sturdy type that likes to run from git:

    rake install

Or, if you've eschewed the convenience of Rubygems entirely, then you
presumably know what to do already.


# Usage

Before you do anything, load the code:

    require "pwnedkeys/filter"

The following illustrative examples do not show the full capabilities of the
gem.  The [API documentation](https://rubydoc.info/gems/pwnedkeys-filter) gives
all the possibilities.


## Querying the filter

Open the filter file, then call `#probably_includes?` with a key:

    filter = Pwnedkeys::Filter.open("/path/to/the/filter/data/file")
    key    = OpenSSL::PKey::RSA.new(2048)

    # if this returns `true`, it's not your lucky day
    filter.probably_includes?(key)

    # From https://pwnedkeys.com/examples/rsa2048_key.pem
    key = OpenSSL::PKey.read(File.read("pwnedkeys_demo_rsa2048.pem"))

    # This should definitely return `true`
    filter.probably_includes?(key)

Essentially, when passed anything that looks suspiciously like a key, the
`#probably_includes?` method will return `true` if the key is *probably* in the
dataset, and will return `false` if the key is *definitely not* in the dataset.
For more on why the answers are "definitely not" and "probably", it's best to
read [the wikipedia page on bloom
filters](https://en.wikipedia.org/wiki/Bloom_filter).


## Creating a new filter file

To create a new filter data file:

    Pwnedkeys::Filter.create("/some/file/name", hash_count: 4, hash_length: 12)

This does not return an open filter file, it merely creates a new file on
disk, initialized appropriately.


## Adding new entries to a filter file

To add entries to an open filter:

    filter.add(key)

When you're done adding entries:

    filter.close

The API takes care of updating the filter metadata automatically.

If you don't want to have to manually close the filter (and who does, really?),
then the block form of `#open` is for you:

    Pwnedkeys::Filter.open("/filter/file") do |filter|
      filter.add(key)
    end


# Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md).


# Licence

Unless otherwise stated, everything in this repo is covered by the following
copyright notice:

    Copyright (C) 2019  Matt Palmer <matt@hezmatt.org>

    This program is free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License version 3, as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
