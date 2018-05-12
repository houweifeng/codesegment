# -*- coding: utf-8 -*-

from lxml import etree
import requests
import csv
import re

# proxies = { "http": "http://127.0.0.1:9999", "https": "http://127.0.0.1:9999", }

def get_jd_item_info(keyword, dbname, columns):
    search_url = 'https://search.jd.com/Search?keyword=电动车&enc=utf-8'
    selector = etree.HTML(requests.get(search_url).content)
    items = selector.xpath("//div[@id='J_goodsList']//img[@data-sku]")
    data_skus = [item.attrib['data-sku'] for item in items]

    item_map = dict()
    for data_sku in data_skus:
        item_url = 'https://item.jd.com/%s.html' % data_sku
        item_data = requests.get(item_url).content
        selector = etree.HTML(item_data)
        info_area = selector.xpath("//div[@class='p-parameter']//li")
        attrib_map = dict()
        for info in info_area:
            key, val = tuple(info.text.encode('utf-8').split('：'))
            match_column = None
            if key in columns:
                match_column = key
            else:
                for column in columns:
                    if key in column.split('_'):
                        match_column = column
            if match_column:
                gp = re.match(r'^([0-9.-]+)', val)
                if gp is not None and len(gp.groups()) > 0:
                    attrib_map[match_column] = gp.groups()[0]
        # 补全
        for column in columns:
            if column not in attrib_map:
                attrib_map[column] = '-'
                print data_sku
        item_map[data_sku] = attrib_map

    with open(dbname, 'w') as csvfile:
        header_row = ','.join(columns)
        csvfile.write(header_row + '\n')
        for indx in item_map:
            row = ','.join([item_map[indx][column] for column in columns])
            csvfile.write(row + '\n')


# columns = ['商品编号', '重量_净重_商品毛重', '理论时速', '理论续航', '价位', '电压']
# get_jd_item_info('电动车', 'diandongche.csv', columns)