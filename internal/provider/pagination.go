package provider

func buildPaginatedResponse(page, pageSize, total int, collectionKey string, items []map[string]any) map[string]any {
	return map[string]any{
		"page":        page,
		"pageSize":    pageSize,
		"page_size":   pageSize,
		"totalCount":  total,
		"total_count": total,
		"data":        items,
		collectionKey: items,
	}
}
