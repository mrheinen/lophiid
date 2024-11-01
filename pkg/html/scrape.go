package html

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

// ExtractResourceLinks parses an HTML string and returns an array of unique resource links
func ExtractResourceLinks(baseUrl string, htmlContent string) []string {
	// Set to track unique links
	resourceLinks := make(map[string]bool)

	// Resource attribute mappings
	resourceAttributes := map[string][]string{
		"link":   {"href"},   // CSS, icons, fonts
		"script": {"src"},    // JavaScript
		"img":    {"src"},    // Images
		"source": {"srcset"}, // Responsive images, video/audio sources
		"video":  {"src"},    // Video sources
		"audio":  {"src"},    // Audio sources
		"input":  {"src"},    // Input element sources
		"iframe": {"src"},    // Embedded content
	}

	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		return []string{}
	}

	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		if n.Type == html.ElementNode {
			// Check if the element is in our resource attributes map
			attrs, exists := resourceAttributes[n.Data]
			if exists {
				// Check each specified attribute
				for _, attrName := range attrs {
					for _, a := range n.Attr {
						if strings.EqualFold(a.Key, attrName) && a.Val != "" {
							normalizedLink, err := normalizeLink(baseUrl, a.Val)
							if err == nil {
								resourceLinks[normalizedLink] = true
							}
						}
					}
				}
			}
		}

		// Recursively traverse child nodes
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c)
		}
	}

	// Start traversing from the root
	traverse(doc)

	// Convert map keys to slice
	links := make([]string, 0, len(resourceLinks))
	for link := range resourceLinks {
		links = append(links, link)
	}

	return links
}

func getSchemeFromUrl(url string) string {
	sRegex, _ := regexp.Compile(`^[a-zA-Z]+:`)
	return strings.ToLower(sRegex.FindString(url))
}

func toUrlPath(sourceUrl string) (string, error) {
	parsedUrl, err := url.Parse(sourceUrl)
	if err != nil {
		return "", fmt.Errorf("failed to parse link: %s", sourceUrl)
	}

	if parsedUrl.Path == "" || parsedUrl.Path == "/" || parsedUrl.Path[len(parsedUrl.Path)-1] == '/' {
		return fmt.Sprintf("%s://%s%s", parsedUrl.Scheme, parsedUrl.Host, parsedUrl.Path), nil
	}

	parts := strings.Split(parsedUrl.Path, "/")
	if strings.Contains(parts[len(parts)-1], ".") {
		parts = parts[:len(parts)-1]
	}

	return fmt.Sprintf("%s://%s/%s", parsedUrl.Scheme, parsedUrl.Host, strings.Join(parts, "/")), nil

}

// normalizeLink handles relative and absolute URLs
func normalizeLink(baseUrl string, link string) (string, error) {
	link = strings.TrimSpace(link)

	// Remove fragment identifiers
	if fragmentIndex := strings.Index(link, "#"); fragmentIndex != -1 {
		link = link[:fragmentIndex]
	}

	if link == "" {
		return "", errors.New("ignoring empty link")
	}

	scheme := getSchemeFromUrl(link)
	if scheme != "" {
		if scheme != "http:" && scheme != "https:" {
			return "", fmt.Errorf("invalid scheme: %s", scheme)
		} else {
			return link, nil
		}
	}

	if strings.HasPrefix(link, "//") {
		baseScheme := getSchemeFromUrl(baseUrl)
		return baseScheme + link, nil
	}

	if link[0] == '/' {
		parsedUrl, err := url.Parse(baseUrl)
		if err != nil {
			return "", fmt.Errorf("failed to parse link: %s", link)
		}

		return fmt.Sprintf("%s://%s%s", parsedUrl.Scheme, parsedUrl.Host, link), nil
	}

	urlPath, err := toUrlPath(baseUrl)
	if err != nil {
		return "", fmt.Errorf("failed to parse base url: %s", baseUrl)
	}

	if urlPath[len(urlPath)-1] == '/' {
		urlPath = urlPath[:len(urlPath)-1]
	}

	return fmt.Sprintf("%s/%s", urlPath, link), nil
}
