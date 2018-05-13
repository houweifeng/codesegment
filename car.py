from lxml import etree
import requests
import json
import csv
import re

'https://cars.app.autohome.com.cn/cfg_v8.5.0/cars/speccompare.ashx?specids=30000 '


def tryget(url):
    for trytime in range(0, 10):
        try:
            return requests.get(url).content
        except:
            pass

def get_car_item_info(dbname):
    item_map = dict()
    columns = set()

    for carindex in range(1, 40000):
        car_url = 'https://cars.app.autohome.com.cn/cfg_v8.5.0/cars/specc ompare.ashx?specids=%d' % carindex
        try:
            jdata = json.loads(tryget(car_url))
        except:
            print('%d parse failed' % carindex)
            continue
        if 'result' not in jdata or 'paramitems' not in jdata['result']:
            print('%d empty_1' % carindex)
            continue
        paramitems = jdata['result']['paramitems']
        if len(paramitems) == 0:
            print('%d empty_2' % carindex)
            continue
        fl_jdata = dict()
        for bitem in paramitems:
            if 'items' not in bitem:
                continue
            for sitem in bitem['items']:
                if 'modelexcessids' not in sitem or 'name' not in sitem:
                    continue
                modelexcessids = sitem['modelexcessids']
                if len(modelexcessids) == 0 or 'value' not in modelexcessids[0]:
                    continue
                fl_jdata[sitem['name']] = modelexcessids[0]['value']
        if 'specinfo' in jdata['result']:
            specinfo = jdata['result']['specinfo']
            if 'specitems' in specinfo and len(specinfo['specitems']) > 0:
                t_item = specinfo['specitems'][0]
                if 'seriesid' in t_item:
                    fl_jdata['seriesid'] = str(t_item['seriesid'])
                if 'seriesname' in t_item:
                    fl_jdata['seriesname'] = t_item['seriesname']
                if 'specid' in t_item:
                    fl_jdata['specid'] = str(t_item['specid'])
        columns |= set(fl_jdata.keys())

        item_map[carindex] = fl_jdata
        print('handle index %d' % carindex)

    # fix column
    for indx in item_map:
        for column in columns:
            if column not in item_map[indx]:
                item_map[indx][column] = '-'

    with open(dbname, 'w') as csvfile:
        header_row = ','.join(columns)
        csvfile.write(header_row.encode('utf-8') + '\n')
        for indx in item_map:
            row = ','.join([item_map[indx][column] for column in columns])
            csvfile.write(row.encode('utf-8') + '\n')

get_car_item_info('car.csv')