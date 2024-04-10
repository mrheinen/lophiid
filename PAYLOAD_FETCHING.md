# Payload fetching

## Introduction

Worms and hack attempts often contain payloads to execute code on the target.
Such code is very often simple and just serves a purpose of downloading more
complex logic to the server. E.g. a backdoor or worm.

Lophiid will parse URLs from the requests it receives, fetches them and stores
the result on disk.


## Process

URLs are extracted from the requests and scheduled for fetching. The fetching is
done via the honeypots. 

If the fetched content looks like a script, then we will try to extract URLs from
that script and also download these. This however is limited to URLs that are on
the same host as the script itself (in order to reduce noice).

After the content is fetched the URL and the file itself are submitted to virus
total and once the results are available you can find them in the UI.

## Controls

When a URL is fetched; the downloader will first resolve any hostnames and will
check that the IP address is not private and also not one of the honeypots. The
fetching then uses the IP address and not the hostname (prevent TOCTOU issues)
although the hostname is set in the Host header.


