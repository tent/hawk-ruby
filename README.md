# Hawk [![Build Status](https://travis-ci.org/tent/hawk-ruby.png)](https://travis-ci.org/tent/hawk-ruby)

Ruby implementation of [Hawk HTTP authentication scheme](https://github.com/hueniverse/hawk).

## Installation

Add this line to your application's Gemfile:

    gem 'hawk-auth'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install hawk-auth

## Usage

```
$ irb
> require 'hawk'

> Hawk::Client.build_authorization_header(
>   :credentials => {
>     :id => '123456',
>     :key => '2983d45yun89q',
>     :algorithm => 'sha256'
>   },
>   :ts => 1365898519,
>   :method => 'POST',
>   :path => '/somewhere/over/the/rainbow',
>   :host => 'example.net',
>   :port => 80,
>   :payload => 'something to write about',
>   :ext => 'Bazinga!',
>   :nonce => 'Ygvqdz'
> )
Hawk id="123456", ts="1365898519", nonce="Ygvqdz", hash="LjRmtkSKTW0ObTUyZ7N+vjClKd//KTTdfhF1M4XCuEM=", ext="Bazinga!", mac="07uWxZfesjgR9wGYXMfCPvocryS9ct8Ir6/83zj3A5s="

> Hawk::Client.authenticate(
>   %(Hawk hash="2QfCt3GuY9HQnHWyWD3wX68ZOKbynqlfYmuO2ZBRqtY=", mac="0ysNmHEhwCjww5yQdbVZ1yXQ58CiRkc8O3l+rSk/TZE="),
>   :credentials => {
>     :id => "123456",
>     :key => "2983d45yun89q",
>     :algorithm => "sha256"
>   },
>   :ts => 1365899773,
>   :method => "POST",
>   :path => "/somewhere/over/the/rainbow",
>   :host => "example.net",
>   :port => 80,
>   :payload => "something to write about",
>   :content_type => "text/plain",
>   :nonce => "Ygvqdz",
> )
{ :id => "123456", :key => "2983d45yun89q", :algorithm => "sha256" }

> Hawk::Client.calculate_time_offset(
>   %(Hawk ts="1365741469", tsm="h/Ff6XI1euObD78ZNflapvLKXGuaw1RiLI4Q6Q5sAbM=", error="Some Error Message"),
>   :credentials => { :id => "123456", :key => "2983d45yun89q", :algorithm => "sha256" }
> )
321

> credentials = { :id => "123456", :key => "2983d45yun89q", :algorithm => "sha256" }
{ :id => "123456", :key => "2983d45yun89q", :algorithm => "sha256" }
> Hawk::Server.authenticate(
>   %(Hawk id="123456", ts="1365900371", nonce="Ygvqdz", hash="9LxQVpfaAgyiyNeOgD8TEKP6RnM=", mac="lv54INsJZym8wnME0nQAu5jW6BA="),
>   :method => "POST",
>   :path => "/somewhere/over/the/rainbow",
>   :host => "example.net",
>   :port => 80,
>   :content_type => "text/plain",
>   :credentials_lookup => lambda { |id| id == credentials[:id] ? credentials : nil },
>   :nonce_lookup => lambda { |nonce| },
>   :payload => "something to write about"
> )
{ :id => "123456", :key => "2983d45yun89q", :algorithm => "sha256" }

> res = Hawk::Server.authenticate(
>   %(Hawk id="123456", ts="1365901299", mac="zTu3FSTmdsdSaLHd/DrpeQRkuYzcb0snYYKOmwDwP3w="),
>   :method => "POST",
>   :path => "/somewhere/over/the/rainbow",
>   :host => "example.net",
>   :port => 80,
>   :content_type => "text/plain",
>   :credentials_lookup => lambda { |id| id == credentials[:id] ? credentials : nil },
>   :nonce_lookup => lambda { |nonce| }
> )
#<Hawk::AuthorizationHeader::AuthenticationFailure:0x007f95cba33168 @key=:nonce, @message="Missing nonce", @options={:credentials=>{:id=>"123456", :key=>"2983d45yun89q", :algorithm=>"sha256"}}>
> res.header
Hawk ts="1365901388", tsm="6mdH5DT66UeWlkBC9x2QD7Upt0eYnud9dB7y7xKoEoU=", error="Missing nonce"

> Hawk::Server.build_authorization_header(
>   :credentials => {
>     :id => "123456",
>     :key => "2983d45yun89q",
>     :algorithm => "sha1"
>   },
>   :ts => 1365900682,
>   :method => "POST",
>   :path => "/somewhere/over/the/rainbow",
>   :host => "example.net",
>   :port => 80,
>   :ext => "Bazinga!",
>   :nonce => "Ygvqdz"
> )
Hawk ext="Bazinga!", mac="5D0CgZEXKEdeUFYbE5HQqb7ZooI="
```

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
