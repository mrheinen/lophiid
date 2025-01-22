# Content templating support

The data in Content entries can contain special keywords/macros that will be
expanded by the templating logic to real values.

Whenever you create a Content based on a real live host (e.g. you copy a page
with headers) then some values that are normally dynamic on the page will become
static in the copied Content version.

Using templating you can have those values replaced immediately before serving
the content to an attacker.


## Generating random strings

Cookies and things like csrf tokens should be different for different requests.
In order to achieve this you can make use of the %%STRING macro which can be
embedded in:

- The main content data
- The value of headers

The format of this macro is as follows:

```shell
%%STRING%%<character set>%%<string length>%%
```

For example, to create an alphanumeric string of length 32 you can use the
ranges A-Z, a-z and 0-9 as shown below:

```shell
%%STRING%%A-Za-z0-9%%32%%
```

The supported character ranges are:

- A-Z
- a-z
- A-F
- a-f
- 0-9

Besides that you can also add individual characters to the charset. Say you want
to make a random string using the range 0-9 and the character - and @ use the
following example:

```shell
%%STRING%%0-9-@%%32%%
```

Note that you do not need to escape the single - (but you can if you want to).

## Generating date string

### Cookie expiration date

Use the macro %%COOKIE_EXP_DATE%% as a placeholder for the cookie expiration.
This will be rendered into a date that is based on the current time + 24 hours.
