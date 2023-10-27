package fs

import (
	"bufio"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"github.com/stretchr/testify/assert"
)

func setup(handler func(f string)) {
	filename := "/tmp/tmpfile"
	if file, err := os.Create(filename); err == nil {
		defer file.Close()
		defer os.Remove(filename)
		buffer := bufio.NewWriter(file)
		buffer.WriteString("I'm just a temp. file")
		buffer.Flush()

		handler(filename)
	}
}

func TestGetcd(t *testing.T) {
	out := Getcd(1)
	assert.NotEmpty(t, out)
}

func TestGetwd(t *testing.T) {
	out := Getwd()
	assert.NotEmpty(t, out)
}

func TestAbs(t *testing.T) {
	Convey("Absolute path check", t, func() {
		So(Abs("/tmp"), ShouldEqual, "/tmp")
	})

	out := Abs("")
	assert.NotEmpty(t, out)

	out = Abs("..")
	assert.NotEmpty(t, out)

	out = Abs("~/.")
	assert.NotEmpty(t, out)

	out = Abs("./.")
	assert.NotEmpty(t, out)

	out = Abs("../.")
	assert.NotEmpty(t, out)

}

func TestCopy(t *testing.T) {
	if runtime.GOOS != "windows" {
		Convey("Copy files/directories recursively", t, func() {
			filename := "GoAnywhereFake"
			exec.Command("touch", Abs("~/"+filename)).Run()
			defer os.Remove("/tmp/" + filename)
			err := Copy("~/"+filename, "/tmp")
			So(Exists("/tmp/"+filename), ShouldBeTrue)
			So(err, ShouldBeNil)

			exec.Command("mkdir", Abs("~/GoAnywhere")).Run()
			exec.Command("touch", Abs("~/GoAnywhere/Fake")).Run()
			defer os.RemoveAll("~/GoAnywhere")
			defer os.RemoveAll("/tmp/GoAnywhere")
			err = Copy("~/GoAnywhere", "/tmp")
			So(Exists("/tmp/GoAnywhere"), ShouldBeTrue)
			So(err, ShouldBeNil)
		})
	}

}

func TestExists(t *testing.T) {
	Convey("Checks if the given path exists", t, func() {
		exists := Exists("/tmp")
		So(exists, ShouldBeTrue)

		exists = Exists("/NotExists")
		So(exists, ShouldBeFalse)
	})
}

func TestFind(t *testing.T) {
	var regex = regexp.MustCompile(`.*`)
	paths := Find("/", regex)
	assert.NotNil(t, paths)
}

func TestGlob(t *testing.T) {
	_, err := Glob("./", "*")
	assert.NoError(t, err)
}

func TestIsDir(t *testing.T) {
	setup(func(filename string) {
		flag := IsDir(filename)
		Convey("Checks if the given path is a directory", t, func() {
			So(flag, ShouldBeFalse)
		})
	})

	flag := IsDir("/tmp")
	Convey("Checks if the given path is a directory", t, func() {
		So(flag, ShouldBeTrue)
	})

	flag = IsDir("")
	assert.Equal(t, false, flag)
}

func TestIsFile(t *testing.T) {
	setup(func(filename string) {
		flag := IsFile(filename)
		Convey("Checks if the given path is a file", t, func() {
			So(flag, ShouldBeTrue)
		})
	})

	flag := IsFile("/tmp")
	Convey("Checks if the given path is a file", t, func() {
		So(flag, ShouldBeFalse)
	})

	flag = IsFile("")
	Convey("Checks if the given path is a file", t, func() {
		So(flag, ShouldBeFalse)
	})

}
