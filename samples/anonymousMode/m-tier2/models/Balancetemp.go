package models

type Balancetemp struct {
	User      string `json:",omitempty"`
	Balance   int    `json`
	Returnmsg string `json:",omitempty"`
}
