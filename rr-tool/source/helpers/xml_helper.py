from xml.etree.ElementTree import Element
from helpers.logging_helper import get_logger

logger = get_logger('xml-helper')


def visit(root):
    for child in root:
        print(child.tag, child.attrib)
        visit(child)


def globalFind(root: Element, item: str) -> Element:
    """ Retrieves the first element with name `item`, found left descending
    recursively into the tree composed of children elements of the `root`"""

    result = root.find(item)
    if result is None:
        for child in root:
            result = globalFind(child, item)
            if result is not None:
                return result
    else:
        return result


def modifyElement(root: Element, item: str, value: str):
    """ Sets the value of the first element called `item`, found using the globalFind function on the `root`
    element, to the value passed in `value`"""

    el = globalFind(root, item)
    el.text = value


def deleteElement(root: Element, item: str):
    """ Sets the value of the first element called `item`, found using the globalFind function on the `root`
    element, to the value passed in `value`"""

    result = root.find(item)
    if result is None:
        for child in root:
            result = globalFind(child, item)
            if result is not None:
                child.remove(result)
                return child
    else:
        return result
