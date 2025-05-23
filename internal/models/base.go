package models

import (
	"greendrake/l1/internal/utils"
)

type IBase interface {
	GenIDIfEmpty()
	GenID()
	SetID(id utils.SixID)
}

type Base struct {
	ID utils.SixID `bson:"_id,omitempty" json:"id,omitempty"`
}

func (m *Base) GenIDIfEmpty() {
	if m.ID == (utils.SixID{}) {
		m.GenID()
	}
}

func (m *Base) GenID() {
	m.ID = utils.NewSixID()
}

func (m *Base) SetID(id utils.SixID) {
	m.ID = id
}

func NewBase() Base {
	return Base{
		ID: utils.NewSixID(),
	}
}
