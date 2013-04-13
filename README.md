# Hawk [![Build Status](https://travis-ci.org/tent/hawk-ruby.png)](https://travis-ci.org/tent/hawk-ruby)

Ruby implementation of [Hawk HTTP authentication scheme](https://github.com/hueniverse/hawk).

**Authorization Request Header**

```
Authorization: Hawk id="{credentials id}", ts="{epoch timestamp}", nonce="{nonce}", hash="{hash}", ext="{ext}", mac="{mac}", app="{application id}", d1g="{d1g}"
```

`hash`, `ext`, `app`, and `d1g` should only be included if used in mac function.

**Authorization Response Header**

```
Server-Authorization: Hawk mac="{mac}", hash="{hash}", ext="{ext}"
```

`mac` is constructed using the same params as in the request with the exception of `hash` and `ext` which are replaced with new values.

`hash` and `ext` are both optional.

**MAC Function**

```
base-64(
  hmac-{algorithm (e.g. sha-256)}(
    hawk.{hawk version}.{type}
    {epoch timestamp}
    {nonce}
    {uppercase request method}
    {lowercase request path}
    {lowercase request host}
    {request port}
    {hash (see below) or empty line}
    {ext (optional)}
    {application id (optional)}
    {application id digest (requires application id)}
  )
)
```

**Payload Hash Function**

```
base-64(
  digest-{algorithm (e.g. sha-256)}(
    hawk.#{hawk version}.payload
    {plain content-type (e.g. application/json)}
    {request payload or empty line}
  )
)
```

**Bewit MAC Function**

```
base-64(
  {credentials id} + \ + {expiry epoch timestamp} + \ + hmac-{algorithm (e.g. sha-256)}(
    hawk.{hawk version}.bewit
    {epoch timestamp}
    {nonce}
    {uppercase request method}
    {lowercase request path}
    {lowercase request host}
    {request port}
    {ext (optional)}
  ) + \ + {ext or empty}
)
```

## Installation

Add this line to your application's Gemfile:

    gem 'hawk-auth'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install hawk-auth

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
