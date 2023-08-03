package env

/*
env
===

Ease of Accessing Environment Variables.

## Installation

```shell
$ go get -v github.com/goanywhere/env
```

## Usage

Add the application settings to file `.env` right under the root of your project:

```shell
MY_SECRET_KEY=YOURSECRETKEY
Case_Will_Be_IgNoreD=YOURSECRETKEYGOESHERE
```

You can double/single quote string values:

```shell
PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----HkVN9…-----END DSA PRIVATE KEY-----"
```

You can use `export` in front of each line just like your shell settings.
So that you can `source` the file in your terminal directly:

```shell
export USERNAME=account@goanywhere.io
export PASSWORD=AccountPasswordGoesHere
```

All set now, you are good to Go :-)

``` go
package main

import (
    "github.com/goanywhere/env"
    "github.com/goanywhere/rex"
)

func index (ctx *rex.Context) {
    ctx.HTML("index.html")
}

func main() {
    // Override default 5000 port here.
    env.Set("port", "9394")

    app := rex.New()
    app.Get("/", index)
    app.Serve()
}
```

You will now have the HTTP server running on `0.0.0.0:9394`.


`env` supports namespace (case-insensitive, same as the key).

``` go
import (
    "fmt"
    "github.com/goanywhere/env"
)

func main() {
    env.Set("debug", "false", "production")

    fmt.Printf("debug: %s", env.Get("debug", "production"))
}
```

`env` also supports custom struct for you to access the reflected values (the key is case-insensitive).

``` go
package main

import (
    "fmt"
    "github.com/goanywhere/env"
)

type Spec struct {
    App string
}

func main() {
    var spec Spec

    env.Set("app", "myapplication")
    env.Map(&spec)

    fmt.Printf("App: %s", spec.App)     // output: "App: myapplication"
}
```

We also includes dotenv supports:

``` text
test1  =  value1
test2 = 'value2'
test3 = "value3"
export test4=value4
```

``` go
package main

import (
    "fmt"

    "github.com/goanywhere/env"
)

func main() {
    // Load '.env' from current working directory.
    env.Load(".env")

    fmt.Printf("<test: %s>", env.Get("test"))     // output: "value"
    fmt.Printf("<test2: %s>", env.Get("test2"))   // output: "value2"
}
```


## NOTES

Sensitive settings should **ONLY** be accessible on the machines that need access to them.
**NEVER** commit them to a repository (even a private one) that is not needed by every development machine and server.
*/
