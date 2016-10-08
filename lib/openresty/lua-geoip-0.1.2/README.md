lua-geoip — bindings for MaxMind GeoIP library
==============================================

See the copyright information in the file named `COPYRIGHT`.

## API

* `require 'geoip'`

### Enums

#### DB types

* `geoip.COUNTRY`
* `geoip.COUNTRY_V6`
* `geoip.REGION_REV0`
* `geoip.REGION_REV1`
* `geoip.REGION` = `geoip.REGION_REV1`
* `geoip.CITY_REV0`
* `geoip.CITY_REV1`
* `geoip.CITY` = `geoip.CITY_REV1`
* `geoip.ORG`
* `geoip.ISP`
* `geoip.PROXY`
* `geoip.ASNUM`
* `geoip.NETSPEED`
* `geoip.DOMAIN`

#### Open flags

* `geoip.STANDARD`
* `geoip.MEMORY_CACHE`
* `geoip.CHECK_CACHE`
* `geoip.INDEX_CACHE`
* `geoip.MMAP_CACHE`

#### Charsets

* `geoip.ISO_8859_1`
* `geoip.UTF8`

TODO: Document further. Meanwhile, see tests.

## Where to get stuff?

### On Debian / Ubuntu Using PPA:

MaxMind provides a PPA for recent version of Ubuntu. To add the PPA to your
APT sources, run:

    $ sudo add-apt-repository ppa:maxmind/ppa
    $ sudo apt-get update

Then install the packages by running:

    $ sudo apt-get install geoip-database # GeoLite Country only
    $ sudo apt-get install libgeoip-dev

### Raw

    $ wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCountry/GeoIP.dat.gz
    $ wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz

### C library

    http://www.maxmind.com/app/c
