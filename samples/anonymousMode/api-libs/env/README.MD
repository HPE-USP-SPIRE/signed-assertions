env
===
[![Build Status](https://travis-ci.org/goanywhere/env.svg?branch=master)](https://travis-ci.org/goanywhere/env) [![GoDoc](https://godoc.org/github.com/goanywhere/env?status.svg)](http://godoc.org/github.com/goanywhere/env)

Ease of Accessing Environment Varaibles in Golang

### Installation

```shell
$ go get -v github.com/goanywhere/env
```

### Usage


```shell
PORT=9394
SECRET_KEY=YOURSECRETKEY
```

You can double/single quote string values:

```shell
PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----HkVN9…-----END DSA PRIVATE KEY-----"
```

You can use `export` in front of each line just like your shell settings, so that you can `source` the file in your terminal directly:

```shell
export USERNAME=account@goanywhere.io
export PASSWORD=AccountPasswordGoesHere
```

Export these values, you can then access them using env now.

``` go
package main

import (
    "github.com/goanywhere/env"
)


func main() {
    env.Int("PORT")             // 9394
    env.String("SECRET_KEY")    // YOURSECERTKEY
    .......
}
```


`env` also supports custom struct for you to access the reflected values.

``` go
package main

import (
    "fmt"
    "github.com/goanywhere/env"
)

type Spec struct {
    App         string
    SecretKey   string  `env:"SECRET_KEY"`
}

func main() {
    var spec Spec

    env.Set("App", "myapplication")
    env.Set("SECRET_KEY", "wGv7ELIx8P8qsUit9OuWw2zwPEF0nXtvjIKZQOioAVuI5GnHSwBAeWZ6l4-SpIPT")
    env.Map(&spec)

    fmt.Printf("App: %s", spec.App)             // output: "App: myapplication"
    fmt.Printf("Secret: %s", spec.SecretKey)    // output: "Secret: wGv7ELIx8P8qsUit9OuWw2zwPEF0nXtvjIKZQOioAVuI5GnHSwBAeWZ6l4-SpIPT"
}
```

We also includes dotenv supports, simply add the application settings to file `.env` right under the root of your project:

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
    env.Load()

    fmt.Printf("<test1: %s>", env.String("test1"))  // output: "value1"
    fmt.Printf("<test2: %s>", env.String("test2"))  // output: "value2"
}
```


### NOTES

Sensitive settings should **ONLY** be accessible on the machines that need access to them. **NEVER** commit them to a repository (even a private one) that is not needed by every development machine and server.

