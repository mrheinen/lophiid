# lophiid

<p align="center">
  <img src="./images/logo-small.png" />
</p>

![Lophiid build workflow](https://github.com/mrheinen/lophiid/actions/workflows/go.yml/badge.svg)
![CodeQL](https://github.com/mrheinen/lophiid/actions/workflows/github-code-scanning/codeql/badge.svg)

IMPORTANT: Lophiid is currently being transformed into a hybrid AI honeypot. You can try
our the code in the main branch but keep in mind that a lot of the documentation
needs updating.  The first release is scheduled for the first week of January!


## Introduction

Lophiid is a distributed honeypot for detecting and interacting with mass web
application exploitation attempts.

The design of lophiid is that one backend controls multiple honeypot sensors
agents across the web. Each honeypot can be configured individually but the
backend is able to track interactions with attackers across all of them.

Say an attacker scans for / across the internet and it hits 50 lophiid
honeypots. The backend can make sure that during each individual interaction
with a honeypot a different response is send to the attacker and with that
increases the chance that the attacker gets something they are looking for which
can result in further interaction.

Similarly lophiid can respond differently to multiple command injections against
the same endpoint.

Key features:

- A distributed honeypot approach
- Rule based interactions with attacks
- Static, scripted (Javascript) and AI supported response handling
- Alerting possible (Telegram, extensible)
- UI with comprehensive search
- AI analysis of attacks
- Automatic tagging of requests and attacks to help triage
- Automatically malware collection and storage
- Yara (yara-x) integration
- Direct integration with VirusTotal
- Ratelimiting / DoS protection
- Exporting of rules for sharing with the community
- Extensive metrics for prometheus/grafana
- Highly customizable

Running lophiid is already very interesting and you'll collect a lot of threat
information. The project is still in an early phase of development though and
large changes are still to be expected in the near future.

For more information check out the [Detailed Description](./DETAILED_DESCRIPTION.md) document and get started with the
[Setup](./SETUP.md) guide.

Don't hesitate to reach out to niels.heinen{at}gmail.com for any assistance.

# Screenshots

Requests page overview which shows all the requests that honeypots are getting.
![Requests overview](./images/screenshot-requests-wget.png)

The downloads page shows information about all the downloaded payloads which
were obtained via attacks. The payloads themselves are also stored locally in
the malware directory (configurable via the backend config).
![Downloads page](./images/screenshot-payloads.png)


# Contributing

Contributions are super welcome! Just fork the repo and send us a PR. Please
regularly check the [CONTRIBUTING.md](./CONTRIBUTING.md) for general guidelines

# Documentation

* [Setup guide](./SETUP.md)
* [Detailed Description](./DETAILED_DESCRIPTION.md)
* [Screenshots](./SCREENSHOTS.md)
* [Scripted responses](./SCRIPTING.md)
* [API cli client usage](./API_CLIENT.md)
* [UI search - overview](./SEARCH.md)
* [UI search - all keywords](./SEARCH_KEYWORDS.md)
* [Payload fetching](./PAYLOAD_FETCHING.md)
