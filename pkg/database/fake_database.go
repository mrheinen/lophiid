// Lophiid distributed honeypot
// Copyright (C) 2025 Niels Heinen
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the
// Free Software Foundation; either version 2 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
// for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
package database

import (
	"fmt"
	"lophiid/pkg/database/models"
	"strconv"
	"strings"
)

// FakeDatabaseClient is a struct specifically for testing users of the
// DatabaseClient interface
type FakeDatabaseClient struct {
	ContentIDToReturn               int64
	ContentsToReturn                map[int64]models.Content
	ErrorToReturn                   error
	UpdateErrorToReturn             error
	ContentRuleIDToReturn           int64
	ContentRulesToReturn            []models.ContentRule
	RequestsToReturn                []models.Request
	RequestToReturn                 models.Request
	DownloadsToReturn               []models.Download
	ApplicationToReturn             models.Application
	AppErrorToReturn                error
	HoneypotToReturn                models.Honeypot
	HoneypotErrorToReturn           error
	QueriesToReturn                 []models.StoredQuery
	QueriesToReturnError            error
	TagPerQueryReturn               []models.TagPerQuery
	TagPerQueryReturnError          error
	WhoisModelsToReturn             []models.Whois
	WhoisErrorToReturn              error
	LastDataModelSeen               any
	LastExternalDataModelSeen       any
	P0fResultToReturn               models.P0fResult
	P0fErrorToReturn                error
	IpEventToReturn                 models.IpEvent
	DataModelToReturn               models.DataModel
	SessionToReturn                 models.Session
	RequestDescriptionsToReturn     []models.RequestDescription
	MetadataToReturn                []models.RequestMetadata
	YarasToReturn                   []models.Yara
	SimpleQueryResult               any
	SessionExecutionContextToReturn []models.SessionExecutionContext
	TagsPerRuleToReturn             []models.TagPerRule
	AppPerGroupToReturn            []models.AppPerGroup
	RuleGroupToReturn               []models.RuleGroup
	AppPerGroupJoinToReturn         []models.AppPerGroupJoin
	ContentRulesByAppIDToReturn     map[int64][]models.ContentRule
}

func (f *FakeDatabaseClient) Close() {}
func (f *FakeDatabaseClient) GetContentRuleByID(id int64) (models.ContentRule, error) {
	return f.ContentRulesToReturn[0], f.ErrorToReturn
}
func (f *FakeDatabaseClient) GetContentByID(id int64) (models.Content, error) {
	ct, ok := f.ContentsToReturn[id]
	if !ok {
		return ct, fmt.Errorf("not found")
	}
	return ct, f.ErrorToReturn
}
func (f *FakeDatabaseClient) Insert(dm models.DataModel) (models.DataModel, error) {
	f.LastDataModelSeen = dm
	return dm, f.ErrorToReturn
}
func (f *FakeDatabaseClient) InsertExternalModel(dm models.ExternalDataModel) (models.DataModel, error) {
	f.LastExternalDataModelSeen = dm
	return dm, f.ErrorToReturn
}
func (f *FakeDatabaseClient) Update(dm models.DataModel) error {
	f.LastDataModelSeen = dm
	if f.UpdateErrorToReturn != nil {
		return f.UpdateErrorToReturn
	}
	return f.ErrorToReturn
}
func (f *FakeDatabaseClient) Delete(dm models.DataModel) error {
	return f.ErrorToReturn
}
func (f *FakeDatabaseClient) GetMetadataByRequestID(id int64) ([]models.RequestMetadata, error) {
	return f.MetadataToReturn, f.ErrorToReturn
}
func (f *FakeDatabaseClient) SearchRequests(offset int64, limit int64, query string) ([]models.Request, error) {
	return f.RequestsToReturn, f.ErrorToReturn
}
func (f *FakeDatabaseClient) SearchEvents(offset int64, limit int64, query string) ([]models.IpEvent, error) {
	return []models.IpEvent{f.IpEventToReturn}, f.ErrorToReturn
}
func (f *FakeDatabaseClient) SearchContentRules(offset int64, limit int64, query string) ([]models.ContentRule, error) {
	if f.ContentRulesByAppIDToReturn != nil && strings.HasPrefix(query, "app_id:") {
		idStr := strings.TrimPrefix(query, "app_id:")
		appID, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("fake: invalid app_id: %s", idStr)
		}
		return f.ContentRulesByAppIDToReturn[appID], f.ErrorToReturn
	}
	return f.ContentRulesToReturn, f.ErrorToReturn
}
func (f *FakeDatabaseClient) SearchYara(offset int64, limit int64, query string) ([]models.Yara, error) {
	return f.YarasToReturn, f.ErrorToReturn
}
func (f *FakeDatabaseClient) SearchSessionExecutionContext(offset int64, limit int64, query string) ([]models.SessionExecutionContext, error) {
	return f.SessionExecutionContextToReturn, f.ErrorToReturn
}
func (f *FakeDatabaseClient) SearchSession(offset int64, limit int64, query string) ([]models.Session, error) {
	return []models.Session{f.SessionToReturn}, f.ErrorToReturn
}
func (f *FakeDatabaseClient) SearchContent(offset int64, limit int64, query string) ([]models.Content, error) {
	var ret []models.Content
	for _, v := range f.ContentsToReturn {
		ret = append(ret, v)
	}
	return ret, f.ErrorToReturn
}
func (f *FakeDatabaseClient) GetAppByID(id int64) (models.Application, error) {
	return f.ApplicationToReturn, f.AppErrorToReturn
}
func (f *FakeDatabaseClient) GetAppPerGroupJoin() ([]models.AppPerGroupJoin, error) {
	return f.AppPerGroupJoinToReturn, f.ErrorToReturn
}
func (f *FakeDatabaseClient) ReplaceAppsForGroup(groupID int64, appIDs []int64) error {
	return f.ErrorToReturn
}
func (f *FakeDatabaseClient) SearchApps(offset int64, limit int64, query string) ([]models.Application, error) {
	return []models.Application{f.ApplicationToReturn}, nil
}
func (f *FakeDatabaseClient) SearchDownloads(offset int64, limit int64, query string) ([]models.Download, error) {
	return f.DownloadsToReturn, f.ErrorToReturn
}
func (f *FakeDatabaseClient) SearchHoneypots(offset int64, limit int64, query string) ([]models.Honeypot, error) {
	return []models.Honeypot{f.HoneypotToReturn}, f.HoneypotErrorToReturn
}
func (f *FakeDatabaseClient) SearchStoredQuery(offset int64, limit int64, query string) ([]models.StoredQuery, error) {
	return f.QueriesToReturn, f.QueriesToReturnError
}
func (f *FakeDatabaseClient) SearchTags(offset int64, limit int64, query string) ([]models.Tag, error) {
	return []models.Tag{}, nil
}
func (f *FakeDatabaseClient) SearchTagPerQuery(offset int64, limit int64, query string) ([]models.TagPerQuery, error) {
	return f.TagPerQueryReturn, f.TagPerQueryReturnError
}
func (f *FakeDatabaseClient) SearchTagPerRequest(offset int64, limit int64, query string) ([]models.TagPerRequest, error) {
	return []models.TagPerRequest{}, nil
}
func (f *FakeDatabaseClient) GetTagsPerRequestForRequestID(id int64) ([]models.TagPerRequest, error) {
	return []models.TagPerRequest{}, nil
}
func (f *FakeDatabaseClient) GetTagPerRequestFullForRequest(id int64) ([]models.TagPerRequestFull, error) {
	return []models.TagPerRequestFull{}, nil
}
func (f *FakeDatabaseClient) GetP0fResultByIP(ip string, querySuffix string) (models.P0fResult, error) {
	return f.P0fResultToReturn, f.P0fErrorToReturn
}
func (f *FakeDatabaseClient) GetRequestByID(id int64) (models.Request, error) {
	return f.RequestToReturn, f.ErrorToReturn
}
func (f *FakeDatabaseClient) SearchWhois(offset int64, limit int64, query string) ([]models.Whois, error) {
	return f.WhoisModelsToReturn, f.WhoisErrorToReturn
}
func (f *FakeDatabaseClient) SearchRequestDescription(offset int64, limit int64, query string) ([]models.RequestDescription, error) {
	return f.RequestDescriptionsToReturn, f.ErrorToReturn
}
func (f *FakeDatabaseClient) SearchTagPerRule(offset int64, limit int64, query string) ([]models.TagPerRule, error) {
	return f.TagsPerRuleToReturn, f.ErrorToReturn
}
func (f *FakeDatabaseClient) SimpleQuery(query string, result any) (any, error) {
	return f.SimpleQueryResult, f.ErrorToReturn
}
func (f *FakeDatabaseClient) SearchAppPerGroup(offset int64, limit int64, query string) ([]models.AppPerGroup, error) {
	return f.AppPerGroupToReturn, f.ErrorToReturn
}
func (f *FakeDatabaseClient) SearchRuleGroup(offset int64, limit int64, query string) ([]models.RuleGroup, error) {
	return f.RuleGroupToReturn, f.ErrorToReturn
}
