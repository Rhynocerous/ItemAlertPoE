#!/usr/bin/env python
# -*- coding: ISO-8859-1 -*-

'''
sku wrote this program. As long as you retain this notice you
can do whatever you want with this stuff. If we meet some day, and you think
this stuff is worth it, you can buy me a beer in return.
'''

def shouldNotify(itemName):
    return True if not _filterItems else itemName in getNotifyItems()

def getNotifyItems():
    return _notifyItems


# Set this to True if you want to filter items and only announce
# items that have been added to the _notifyItems list.
# If _filterItems is False, ItemAlertPoE will announce every item drop.
_filterItems = True

# Add items that you wish to announce to this list.
# This list is only considered if _filterItems is set to True.
# If the item name countains a single quote, either escape it
# using \' or use double quotes like in the example below.
_notifyItems = []
_notifyItems.append("Driftwood Wand")