#! /usr/bin/env python
# # -*- coding: utf-8 -*-

from selenium import webdriver
from pdfkit import from_string
from urllib.parse import unquote, quote
from bs4 import BeautifulSoup
import requests

fireFoxOptions = webdriver.FirefoxOptions()
fireFoxOptions.set_headless()
browser = webdriver.Firefox(firefox_options=fireFoxOptions)

def jobbole(url):
    parts = url.split('/')
    baseurl = parts[0] + '//' + parts[2]
    content_path = "//div[@class='entry']"
    title_path = "//div[@class='entry-header']/h1"
    try:
        browser.get(url)
        content = browser.find_element_by_xpath(content_path)
        title = browser.find_element_by_xpath(title_path).text
        if title.find('失踪') >= 0:
            return
        filter_html = '<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"/></head><body>'
        filter_html += '<br>本文转载自<a href="%s">%s<a><br>' % (url, url)
        filter_html += content.get_property('innerHTML')
        filter_html += '</body></html>'
        for item in content.find_elements_by_xpath("//img"):
            src = unquote(item.get_property('src').replace(baseurl, ''))
            filter_html = filter_html.replace(src, baseurl + src)
        with open('test.html', 'w') as f:
            f.write(filter_html)
        title = ''.join([c for c in title if c not in '/\\:* =<>; 、|"\''])
        from_string(filter_html,  title + '.pdf')
    except Exception as e:
        print(e, url)
        return False
    return True

def boke112(url):
    parts = url.split('/')
    baseurl = parts[0] + '//' + parts[2]
    content_path = "//div[@class='entry-content']"
    title_path = "//h1[@class='entry-title']"
    try:
        browser.get(url)
        content = browser.find_element_by_xpath(content_path)
        title = browser.find_element_by_xpath(title_path).text
        if title.find('失踪') >= 0 or title.find('Not Found') >= 0:
            return False
        filter_html = '<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"/></head><body>'
        filter_html += '<br>本文转载自<a href="%s">%s<a><br>' % (url, url)
        filter_html += content.get_property('innerHTML')
        filter_html += '</body></html>'
        for item in content.find_elements_by_xpath("//img"):
            if not item.get_property('src').startswith(baseurl):
                continue
            src = unquote(item.get_property('src').replace(baseurl, ''))
            filter_html = filter_html.replace(src, baseurl + quote(src))
        with open('test.html', 'w') as f:
            f.write(filter_html)
        title = ''.join([c for c in title if c not in '/\\:* =<>; 、|"\''])
        from_string(filter_html,  title + '.pdf')
    except Exception as e:
        print(e, url)
        return False
    return True

def jianshu(url):
    print(url)
    parts = url.split('/')
    baseurl = parts[0] + '//' + parts[2]
    content_path = "//div[@class='show-content-free']"
    title_path = "//h1[@class='title']"
    try:
        browser.get(url)
        content = browser.find_element_by_xpath(content_path)
        title = browser.find_element_by_xpath(title_path).text
        if title.find('失踪') >= 0 or title.find('Not Found') >= 0:
            return False
        filter_html = '<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"/></head><body>'
        filter_html += '<br>本文转载自<a href="%s">%s<a><br>' % (url, url)
        filter_html += content.get_property('innerHTML')
        filter_html += '</body></html>'
        for item in content.find_elements_by_xpath("//img"):
            if not item.get_property('src').startswith(baseurl):
                continue
            src = unquote(item.get_property('src').replace(baseurl, ''))
            filter_html = filter_html.replace(src, baseurl + quote(src))
        with open('test.html', 'w') as f:
            f.write(filter_html)
        title = ''.join([c for c in title if c not in '/\\:* =<>; 、|"\''])
        from_string(filter_html, title + '.pdf')
    except Exception as e:
        print(e, url)
        return False
    return True

def runjobbole():
    for i in range(1923, 120000):
        jobbole('http://blog.jobbole.com/%d/' % i)
        jobbole('http://www.importnew.com/%d/' % i)

def runboke112():
    for i in range(4816, 1000000):
        boke112('https://boke112.com/%d.html' % i)

def doforurl(baseurl):
    try:
        browser.get(baseurl)
        title = browser.find_element_by_xpath("//h1[@class='title']").text
        content = browser.find_element_by_xpath("//div[@class='show-content-free']")
        filter_html = '<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"/></head><body>'
        filter_html += '<br>本文转载自<a href="%s">%s<a><br>' % (baseurl, baseurl)
        filter_html += content.get_property('innerHTML')
        filter_html += '</body></html>'
        if len(filter_html) < 10000:
            return True
        for item in content.find_elements_by_xpath("//img"):
            if not item.get_property('src').startswith(baseurl):
                continue
            src = unquote(item.get_property('src').replace(baseurl, ''))
            filter_html = filter_html.replace(src, baseurl + quote(src))
        with open('test.html', 'w') as f:
            f.write(filter_html)
        title = ''.join([c for c in title if c not in '/\\:* =<>; 、|"\''])
        from_string(filter_html,  title + '.pdf')
    except Exception as e:
        print(e)
        return False
    return True

def checkforurl(url):
    try:
        browser.get(url)
        browser.find_element_by_xpath("//h1[@class='title']")
        browser.find_element_by_xpath("//div[@class='show-content-free']")
    except Exception as e:
        return False
    return True

def tranverse(url, urllist, skiplist):
    print(url)
    browser.get(url)
    raw_url_list = [ href_c.get_property('href').strip('/') for href_c in browser.find_elements_by_xpath('//a')]
    for href in raw_url_list:
        is_in_skip = False
        for skip in skiplist:
            if href.find(skip) >= 0:
                is_in_skip = True
                break
        if is_in_skip or href in urllist or not href.startswith(url) or href == url:
            continue
        if checkforurl(href):
            urllist.add(href)
        tranverse(href, urllist, skiplist)

def runjianshu():
    headers = {
        "X-PJAX": "true",
        "X-Requested-With": "XMLHttpRequest",
        "Host": "www.jianshu.com",
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:65.0) Gecko/20100101 Firefox/65.0"
    }
    for index in range(0, 1000):
        try:
            req = requests.post(url='https://www.jianshu.com/trending_notes', verify=False,
                                  data=b'page=%d' % index, headers=headers)
            soup = BeautifulSoup(req.text, 'html.parser', from_encoding='utf-8')
            for item in soup.find_all('a'):
                print(item)
        except Exception as e:
            continue
    '''
    target_set = set(list())
    tranverse('https://www.jianshu.com', target_set, [ 'sign_up', 'sign_in', 'writer#' ])
    for item in target_set:
        print(item)
    for target in target_set:
        doforurl(target)
    '''

#runjianshu()
runboke112()
