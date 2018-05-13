# -*- coding: utf-8 -*-

from lxml import etree
import requests
import csv
import re

# proxies = { "http": "http://127.0.0.1:9999", "https": "http://127.0.0.1:9999", }

def tryget(url):
    for trytime in range(0, 10):
        try:
            return requests.get(url).content
        except:
            pass

def get_jd_item_info(keyword, dbname, columns):
    item_map = dict()

    for page_start in range(1, 50):
        search_url = 'https://search.jd.com/Search?keyword=%s&enc=utf-8&page=%d' % (keyword, page_start)
        selector = etree.HTML(tryget(search_url))
        items = selector.xpath("//div[@id='J_goodsList']//li[@data-sku]")
        data_skus = [item.attrib['data-sku'] for item in items]
        if len(data_skus) == 0:
            break
        for data_sku in data_skus:
            item_url = 'https://item.jd.com/%s.html' % data_sku
            selector = etree.HTML(tryget(item_url))
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
                    if columns[match_column]['type'] == 'int':
                        gp = re.match(r'^([0-9.-]+)', val)
                        if gp is not None and len(gp.groups()) > 0:
                            attrib_map[match_column] = int(gp.groups()[0])
                    elif columns[match_column]['type'] == 'str':
                        attrib_map[match_column] = str(val)
            # 其他信息
            # 补全
            valid = True
            for column in columns:
                if column not in attrib_map:
                    if columns[column]['need']:
                        valid = False
                        break
                    attrib_map[column] = '-'
            if valid:
                item_map[data_sku] = attrib_map
        print('handle page %d' % page_start)

    with open(dbname, 'w') as csvfile:
        header_row = ','.join(columns.keys())
        csvfile.write(header_row + '\n')
        for indx in item_map:
            row = ','.join([item_map[indx][column] for column in columns])
            csvfile.write(row + '\n')


diandongche_columns = {
    '商品名称': { 'need': True, 'type': 'str' },
    '商品编号': { 'need': True, 'type': 'str' },
    '重量_净重_商品毛重': { 'need': True, 'type': 'str' },
    '款式': { 'need': False, 'type': 'str' },
    '车型': { 'need': False, 'type': 'str' },
    '电池类别': { 'need': False, 'type': 'str' },
    '电池额定容量': { 'need': False, 'type': 'str' },
    '电池可否拆卸': { 'need': False, 'type': 'str' },
    '载重人数': { 'need': False, 'type': 'str' },
    '轮径': {'need': False, 'type': 'str'},
    '是否支持脚踏': {'need': False, 'type': 'str'},
    '理论时速': { 'need': False, 'type': 'str' },
    '理论续航': { 'need': True, 'type': 'str' },
    '价位': { 'need': False, 'type': 'str' },
    '电压': { 'need': False, 'type': 'str' },
}
get_jd_item_info('电动车', 'diandongche.csv', diandongche_columns)

'''
xiyiji_columns = {
    '商品名称': { 'need': True, 'type': 'str' },
    '商品编号': { 'need': True, 'type': 'str' },
    '重量_净重_商品毛重': { 'need': True, 'type': 'str' },
    '产品类型': { 'need': False, 'type': 'str' },
    '洗涤容量': { 'need': False, 'type': 'str' },
    '能效等级': { 'need': True, 'type': 'str' },
    '高度': { 'need': True, 'type': 'str' },
    '宽度': { 'need': True, 'type': 'str' },
    '深度': { 'need': True, 'type': 'str' },
    '电机类型': { 'need': False, 'type': 'str' },
    '排水类型': { 'need': False, 'type': 'str' },
}
get_jd_item_info('洗衣机', 'xiyiji.csv', xiyiji_columns)
'''
'''
bingxiang_columns = {
    '商品名称': { 'need': True, 'type': 'str' },
    '商品编号': { 'need': True, 'type': 'str' },
    '重量_净重_商品毛重': { 'need': True, 'type': 'str' },
    '制冷方式': { 'need': False, 'type': 'str' },
    '压缩机': { 'need': False, 'type': 'str' },
    '能效等级': { 'need': True, 'type': 'str' },
    '高度': { 'need': True, 'type': 'str' },
    '宽度': { 'need': True, 'type': 'str' },
    '深度': { 'need': True, 'type': 'str' },
    '总容积': { 'need': False, 'type': 'str' },
    '面板材质': { 'need': False, 'type': 'str' },
    '门款式': { 'need': False, 'type': 'str' },
}
get_jd_item_info('冰箱', 'bingxiang.csv', bingxiang_columns)
'''
'''
shouji_columns = {
    '商品名称': { 'need': True, 'type': 'str' },
    '商品编号': { 'need': True, 'type': 'str' },
    '重量_净重_商品毛重': { 'need': True, 'type': 'str' },
    '系统': { 'need': False, 'type': 'str' },
    '机身厚度': { 'need': False, 'type': 'str' },
    '电池容量': { 'need': True, 'type': 'str' },
    '运行内存': { 'need': True, 'type': 'str' },
    '机身内存': { 'need': True, 'type': 'str' },
    '前置摄像头像素': { 'need': False, 'type': 'str' },
    '后置摄像头像素': { 'need': False, 'type': 'str'},
}
get_jd_item_info('手机', 'shouji.csv', shouji_columns)
'''
'''
dianshi_columns = {
    '商品名称': { 'need': True, 'type': 'str' },
    '商品编号': { 'need': True, 'type': 'str' },
    '重量_净重_商品毛重': { 'need': True, 'type': 'str' },
    '分辨率': { 'need': False, 'type': 'str' },
    '能效等级': { 'need': True, 'type': 'str' },
    '屏幕尺寸': { 'need': True, 'type': 'str' },
}
get_jd_item_info('电视', 'dianshi.csv', dianshi_columns)
'''
'''
bijiben_columns = {
    '商品名称': { 'need': True, 'type': 'str' },
    '商品编号': { 'need': True, 'type': 'str' },
    '重量_净重_商品毛重': { 'need': True, 'type': 'str' },
    '系统': { 'need': False, 'type': 'str' },
    '分辨率': { 'need': False, 'type': 'str' },
    '屏幕尺寸': { 'need': True, 'type': 'str' },
    '待机时长': { 'need': False, 'type': 'str' },
    '显卡型号': { 'need': False, 'type': 'str' },
    '处理器': { 'need': False, 'type': 'str' },
    '裸机重量': { 'need': False, 'type': 'str' },
    '硬盘容量': { 'need': False, 'type': 'str' },
    '显存容量': { 'need': False, 'type': 'str' },
    '厚度': { 'need': False, 'type': 'str' },
}
get_jd_item_info('笔记本', 'bijiben.csv', bijiben_columns)
'''
'''
chongdianbao_columns = {
    '商品名称': { 'need': True, 'type': 'str' },
    '商品编号': { 'need': True, 'type': 'str' },
    '重量_净重_商品毛重': { 'need': True, 'type': 'str' },
    '外壳材质': { 'need': False, 'type': 'str' },
    '电芯类型': { 'need': True, 'type': 'str' },
    '容量': { 'need': True, 'type': 'str' },
}
get_jd_item_info('移动电源', 'chongdianbao.csv', chongdianbao_columns)
'''
'''
xiangji_columns = {
    '商品名称': { 'need': True, 'type': 'str' },
    '商品编号': { 'need': True, 'type': 'str' },
    '重量_净重_商品毛重': { 'need': True, 'type': 'str' },
    '商品产地': { 'need': False, 'type': 'str' },
    '画幅': { 'need': False, 'type': 'str' },
    '套头': {'need': False, 'type': 'str'},
    '像素': {'need': True, 'type': 'str'},
}
get_jd_item_info('相机', 'xiangji.csv', xiangji_columns)
'''
