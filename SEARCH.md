# Search functionality

## Keywords and operators

Each page that has a search option has a different set of keywords that you can
use. You can get the information in the UI by pressing on the ? icon in the left
side of the search box (types are also documented per keyword).

The syntax for using a keyword is either:

```
keyword<operator><value>
```

Additionally you can quote the values with a single or double quote. E.g.
```
keyword<operator>"<value>"
```

The options for operators are:

|Operator|Supported types|Description|
|---|---|---|
|:|All types|This is used for an exact match. E.g. port:80 or method:"GET"|
|~|String|Used to perform a SQL LIKE match. E.g. to get URIs that contain wget use uri~%wget%. Use the % as a wildcard. |
|>|int64, Time| Returns results where the value is greater than the one given. E.g. port>80|
|<|int64, Time| Returns results where the value is smaller than the one given. E.g. port<1024 |

Note that it is totally fine to use a keyword repeatedly either with or without
negative matching.  This can be useful for a port range such as using this to
get everything with a port 1000-2000: "port>1000 port<2000"

## Negative matching

You can perform a negative match by adding a - character in front of the search
keyword. For example to get all requests that do not match port 80 use this:

```
 -port:80
```

You can combine negative and positive matching keywords so the following works
just fine:

```
-port:80 method:GET
```

## Combining search parameters
By default combining search keywords will result in a big AND query. For
example, if you search on "port:80 method:GET" then the WHERE clause of the
resulting database query will look something like this "WHERE port = 80 AND
method = 'GET'".

It is possible to use OR in the query though. For example the following select
requests that are for port 80 and 443:

```
port:80 OR port:443
````

There is no limit to the amount of OR clauses you can use.  Remember though that
keywords that follow eachother without an OR are automatically considered an AND
situation.

For example, lets say we want to select requests on port 80 if they use GET and
on port 443 if they use POST. You can do this with the following query:

```
port:80 method:GET OR port:443 method:POST
```

## Example queries

Select requests on port 80 that are a POST and where the payload contains the
word "wget":
```
port:80 method:POST body~%wget%
```

Select requests with possible Java code injections:
```
raw~%java.lang.Runtime% OR raw~%java.lang.ProcessBuilder%
```

Select requests with possible bash tcp connections:
```
body~%tcp% body~%dev% OR uri~%tcp% uri~%dev%
```
