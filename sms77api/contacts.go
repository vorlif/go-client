package sms77api

import (
	"context"
	"encoding/json"
)

type ContactsResource resource

type ContactsWriteCode string

const (
	ContactsWriteCodeUnchanged ContactsWriteCode = "151"
	ContactsWriteCodeChanged   ContactsWriteCode = "152"
)

type ContactsAction string

const (
	ContactsActionDelete ContactsAction = "del"
	ContactsActionRead   ContactsAction = "read"
	ContactsActionWrite  ContactsAction = "write"
)

type Contact struct {
	Id    string `json:"ID"`
	Nick  string `json:"Name"`
	Phone string `json:"Number"`
}

type ContactEditParams struct {
	Id    string `json:"id"`
	Nick  string `json:"nick,omitempty"`
	Phone string `json:"empfaenger,omitempty"`
}

type ContactsCreateJsonResponse struct {
	contactsPropReturn
	Id uint64 `json:"id"`
}

type ContactsDeleteParams = contactsParamId

type ContactsDeleteJsonResponse = contactsPropReturn

type ContactsEditJsonResponse = contactsPropReturn

type ContactsReadParams = contactsParamId

type contactsParamAction struct {
	Action ContactsAction `json:"action"`
}

type contactsParamId struct {
	Id uint64 `json:"id,omitempty"`
}

type contactsParamJson struct {
	Json bool `json:"json,omitempty"`
}

type contactsPropReturn struct {
	Return ContactsWriteCode `json:"return"`
}

type contactsReadApiParams struct {
	contactsParamAction
	ContactsReadParams
	contactsParamJson
}

func newReadApiParams(readParams ContactsReadParams, json bool) contactsReadApiParams {
	return contactsReadApiParams{
		contactsParamAction: contactsParamAction{ContactsActionRead},
		contactsParamJson:   contactsParamJson{json},
		ContactsReadParams:  readParams,
	}
}

type contactsCreateApiParams struct {
	contactsParamAction
	contactsParamJson
}

func newContactsCreateApiParams(json bool) contactsCreateApiParams {
	return contactsCreateApiParams{
		contactsParamAction: contactsParamAction{ContactsActionWrite},
		contactsParamJson:   contactsParamJson{json},
	}
}

type contactsDeleteApiParams struct {
	ContactsDeleteParams
	contactsParamAction
	contactsParamJson
}

func newContactsDeleteApiParams(p ContactsDeleteParams, json bool) contactsDeleteApiParams {
	return contactsDeleteApiParams{
		ContactsDeleteParams: p,
		contactsParamAction:  contactsParamAction{ContactsActionDelete},
		contactsParamJson:    contactsParamJson{json},
	}
}

type contactsEditJsonApiParams struct {
	ContactEditParams
	contactsParamAction
	contactsParamJson
}

func newContactsEditJsonApiParams(p ContactEditParams, json bool) contactsEditJsonApiParams {
	return contactsEditJsonApiParams{
		ContactEditParams:   p,
		contactsParamAction: contactsParamAction{ContactsActionWrite},
		contactsParamJson:   contactsParamJson{json},
	}
}

func (api *ContactsResource) request(ctx context.Context, method HttpMethod, params interface{}) (string, error) {
	return api.client.request(ctx, "contacts", string(method), params)
}

func (api *ContactsResource) ReadCsv(p ContactsReadParams) (string, error) {
	return api.ReadCsvContext(context.Background(), p)
}

func (api *ContactsResource) ReadCsvContext(ctx context.Context, p ContactsReadParams) (string, error) {
	return api.request(ctx, HttpMethodGet, newReadApiParams(p, false))
}

func (api *ContactsResource) ReadJson(p ContactsReadParams) (a []Contact, e error) {
	return api.ReadJsonContext(context.Background(), p)
}

func (api *ContactsResource) ReadJsonContext(ctx context.Context, p ContactsReadParams) (a []Contact, e error) {
	s, e := api.request(ctx, HttpMethodGet, newReadApiParams(p, true))

	if nil != e {
		return
	}

	json.Unmarshal([]byte(s), &a)

	return
}

func (api *ContactsResource) CreateCsv() (string, error) {
	return api.CreateCsvContext(context.Background())
}

func (api *ContactsResource) CreateCsvContext(ctx context.Context) (string, error) {
	return api.request(ctx, HttpMethodPost, newContactsCreateApiParams(false))
}

func (api *ContactsResource) CreateJson() (o ContactsCreateJsonResponse, e error) {
	return api.CreateJsonContext(context.Background())
}

func (api *ContactsResource) CreateJsonContext(ctx context.Context) (o ContactsCreateJsonResponse, e error) {
	s, e := api.request(ctx, HttpMethodGet, newContactsCreateApiParams(true))
	if e != nil {
		return
	}

	e = json.Unmarshal([]byte(s), &o)

	return
}

func (api *ContactsResource) DeleteCsv(p ContactsDeleteParams) (string, error) {
	return api.DeleteCsvContext(context.Background(), p)
}

func (api *ContactsResource) DeleteCsvContext(ctx context.Context, p ContactsDeleteParams) (string, error) {
	return api.request(ctx, HttpMethodPost, newContactsDeleteApiParams(p, false))
}

func (api *ContactsResource) DeleteJson(p ContactsDeleteParams) (o ContactsDeleteJsonResponse, e error) {
	return api.DeleteJsonContext(context.Background(), p)
}

func (api *ContactsResource) DeleteJsonContext(ctx context.Context, p ContactsDeleteParams) (o ContactsDeleteJsonResponse, e error) {
	s, e := api.request(ctx, HttpMethodGet, newContactsDeleteApiParams(p, true))
	if e != nil {
		return
	}

	e = json.Unmarshal([]byte(s), &o)

	return
}

func (api *ContactsResource) EditCsv(p ContactEditParams) (string, error) {
	return api.EditCsvContext(context.Background(), p)
}

func (api *ContactsResource) EditCsvContext(ctx context.Context, p ContactEditParams) (string, error) {
	return api.request(ctx, HttpMethodGet, newContactsEditJsonApiParams(p, false))
}

func (api *ContactsResource) EditJson(p ContactEditParams) (o ContactsEditJsonResponse, e error) {
	return api.EditJsonContext(context.Background(), p)
}

func (api *ContactsResource) EditJsonContext(ctx context.Context, p ContactEditParams) (o ContactsEditJsonResponse, e error) {
	s, e := api.request(ctx, HttpMethodGet, newContactsEditJsonApiParams(p, true))
	if e != nil {
		return
	}

	e = json.Unmarshal([]byte(s), &o)

	return
}
