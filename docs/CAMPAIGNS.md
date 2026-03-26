Lophiid can aggregate multiple attacks into campaigns. It does this by looking
for similar malicious requests, clusting them and creating a campaign signature.
Next it will search back in time for requests that also match the campaign
signature.

When a new request is evaluated it will be checked against the campaign
signature. Each element that makes up the signature (e.g. URI, port, source IP,
..) have an indidual weight which can be configured in the
../config/campaign-agent-config.yaml configuration file.  When a fields matches
the campaign signature, its weight is added to a total score and if the score
exceeds a configurable threshold then the request is added to the campaign.

The weight values in the campaign-agent-config.yaml have been carefully selected
to find requests that are similar. You are encouraged to tweak these weight for
your preference. Once you tweak them, run the campaign-agent to generate
campaigns for a small time window. Then look at the results in the UI and repeat
this process until you are happy with the results.

Running the campaign agent for test annd backfill purposes can be done with the
following command:

```shell
go run cmd/campaign_agent/main.go -c ./campaign-agent-config.yaml --backfill --from 2026-03-20T00:00:00Z --to 2026-03-25T00:00:00Z -wipe
```

Now once you are happy with the created campaigns, you can run the tool
continously by running this command:

```shell
go run cmd/campaign_agent/main.go -c ./campaign-agent-config.yaml
```
