# -*- coding: utf-8 -*-

from lxml import etree
import requests
import csv
import re

# proxies = { "http": "http://127.0.0.1:9999", "https": "http://127.0.0.1:9999", }


def get_jd_item_info(keyword, dbname, columns):
    item_map = dict()

    for page_start in range(1, 50):
        search_url = 'https://search.jd.com/Search?keyword=%s&enc=utf-8&page=%d' % (keyword, page_start)
        selector = etree.HTML(requests.get(search_url).content)
        items = selector.xpath("//div[@id='J_goodsList']//li[@data-sku]")
        data_skus = [item.attrib['data-sku'] for item in items]
        if len(data_skus) == 0:
            break
        for data_sku in data_skus:
            item_url = 'https://item.jd.com/%s.html' % data_sku
            item_data = requests.get(item_url).content
            selector = etree.HTML(item_data)
            info_area = selector.xpath("//div[@class='p-parameter']//li")
            attrib_map = dict()
            for info in info_area:
                newt = info.text.encode('utf-8')
                p = newt.find('：')
                key, val = newt[: p], newt[p + 3 :]#tuple(info.text.encode('utf-8').split('：'))
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
            c1 = 0
            for column in columns:
                if column not in attrib_map:
                    attrib_map[column] = '-'
                    c1 += 1
                    # print data_sku
            if c1 < len(columns) - 2:
                item_map[data_sku] = attrib_map
        print('handle page %d' % page_start)

    with open(dbname, 'w') as csvfile:
        header_row = ','.join(columns)
        csvfile.write(header_row + '\n')
        for indx in item_map:
            row = ','.join([item_map[indx][column] for column in columns])
            csvfile.write(row + '\n')


#columns = ['商品编号', '重量_净重_商品毛重', '理论时速', '理论续航', '价位', '电压']
#get_jd_item_info('电动车', 'diandongche.csv', columns)

columns = ['商品编号', '重量_净重_商品毛重', '能效等级', '高度', '宽度', '深度']
get_jd_item_info('冰箱', 'bingxiang.csv', columns)

columns = ['商品编号', '重量_净重_商品毛重', '能效等级', '高度', '宽度', '深度']
get_jd_item_info('洗衣机', 'xiyiji.csv', columns)

columns = ['商品编号', '重量_净重_商品毛重', '能效等级', '商品匹数', '使用面积']
get_jd_item_info('空调', 'kongtiao.csv', columns)
