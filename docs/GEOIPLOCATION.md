As part of the whois lookup logic, the Lophiid backend can also lookup geo IP
information from the offline and free MaxMind databases. To make use of this
you will first need to download the MaxMind databases and store them in a
directory accessible for Lophiid.

Follow instructions on the MaxMind website and then use the tool here to keep
the databases in sync: https://github.com/maxmind/geoipupdate

In the configuration file, you will need to add the following line to make sure
the righ databases are downloaded:

```shell
EditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country
```

After you downloaded the databases, you will need to update the configuration
and make sure the following lines in the whois_manager section exist and have
the correct information:

```shell
whois_manager:
...
...
  geoip_enabled: true
  geoip_db_dir: /path/to/geoip/directory/
```

No need to specify a file name as Lophiid uses multiple files and expects them
to be in the directory.

With all this enabled, you can see the GeoIP information in the UI and you can
also start using GeoIP weights in the configuration of the campaign agent.
