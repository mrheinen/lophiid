# Payload fetching

## Introduction

Worms and hack attempts often contain payloads to execute code on the target.
Such code is very often simple and just serves a purpose of downloading more
complex logic to the server. E.g. a backdoor or worm.

Lophiid will parse URLs from the requests it receives, fetches them and stores
the result on disk.

## Process

URLs are extracted from the requests and scheduled for fetching. The fetching is
done via the honeypots using the following steps:

 - The backend looks for URLs in the requests
 - For every URL, the backend will notify the honeypot to fetch it's content
    - This makes it look like the targetted system does the download
    - This can help fetch data that is geofenced by attackers
 - The honeypot uploads the results to the backend
 - The backend stores the result on disk
    - Using unique file names
    - While writing metadata, such as origin, in a file next to the payload

If the fetched content looks like a script, then the backend will try
to extract URLs from that script and also download these. This however
is limited to URLs that are on the same host as the script itself (in
order to reduce noise).

Parsing URLs from parsed URLs can cause an infinite loop. Therefore this parsing
is only done to a depth of 1.

After the content is fetched the URL and the file itself are submitted to virus
total and once the results are available you can find them in the UI. The
file itself is only submitted if the sha256sum hash of it has not been submitted
before. This in order to keep the Virus Total quota usage low.

## Virus Total interaction

Files and URL uploading to Virus Total is done out-of-band and the resulting
information is considered "extra". The implementation is robust and has fall
back mechanisms to deal with quota issues.

A link to the URL and file analysis is stored with the download in the database
and can be viewed in the UI. We also stored some analysis metadata in the
database and you can search on this in the UI.

## Controls

When a URL is fetched; the downloader will first resolve any hostnames and will
check that the IP address is not private and also not one of the honeypots. The
fetching then uses the IP address and not the hostname (prevent TOCTOU issues)
although the hostname is set in the Host header.

The backend has a download cache and will try to avoid downloading the same
payload repeatedly to prevent abuse. A unique URL is only downloaded every 5
minutes.  We do not want to prevent downloading the same URL multiple times
because the content might have changed.

## Limitations

The backend can't really distinct between links to malware and links to DTD
files. Therefore you can expect occasionally that content is downloaded that
isn't interesting.  Rather download too much than too little.

Some downloads from IoT systems can be extremely slow. You should therefore
configure the downloader HTTP timeout in the config to be long (e.g. at least
10 minutes) to not miss out on anything.  Also quite typical at the time of
writing is that downloads from IoT devices are a one shot opportunity only so
therefore you want the initial download to succeed because there isn't a second
chance.

The maximum download size can be configured in the backend. The backend however
does not monitor your disk usage which you will need to do yourself.  For your
reference; a system with 50 agents running for 7 months has a malware directory
of 1.4GB.
