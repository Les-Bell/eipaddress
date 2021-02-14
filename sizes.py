"""Report the size of an object, including the objects it contains.

This is based on a post by Aaron Hall, at the URL

    https://stackoverflow.com/questions/449560/how-do-i-determine-the-size-of-an-object-in-python/450034

with many improvements:

  * include __slots__ from base classes
  * include __dict__ from base classes
  * include key values from each __dict__
  * exclude built-in objects, they do not add to the size of an object
  * exclude class attributes, they do not add to the size of an object
  * a verbose option, to show the memory used by each  child object
"""

import sys
from numbers import Number
from collections import Set, Mapping, deque
from types import ModuleType, FunctionType
from gc import get_referents

try:  # Python 2
    zero_depth_bases = basestring, Number, xrange, bytearray
    iteritems = 'iteritems'
except NameError:  # Python 3
    zero_depth_bases = str, bytes, Number, range, bytearray
    iteritems = 'items'

# modules, functions and type references do not add to the size of an object
EXCLUDE_TYPES = ModuleType, FunctionType, type

# builtin objects do not add to the size of an object
EXCLUDE_IDS = [id(getattr(__builtins__, x)) for x in dir(__builtins__)]

def class_attrs(obj):
    """Return a list of class attribute names for an object."""
    if hasattr(obj, '__class__'):
        return dir(obj.__class__)
    return []

def is_class_attr(obj, name):
    """Check if a name is is a class attribute of an object.

    Args:
        obj: the object to check.
        name: the attribute name to check for.

    Returns:
        True if name is a class attribute of the object, else False.
    """
    return (name in class_attrs(obj) and
            # the attribute must not be overridden by the object instance
            id(getattr(obj, name)) == id(getattr(obj.__class__, name)))

def _all_dicts(T):
    """ Return a list of all __dict__ for a type, or object.

    Args:
        T: the type, or object, to determine the __dicts__ for.

    Returns:
        The list of __dict__ references, including those in base classes.
    """
    if not isinstance(T, type):
        T = type(T)
    dicts = []
    def inner(T, dicts):
        if hasattr(T, '__dict__'):
            dicts.append(T.__dict__)
        for c in T.__bases__:
            inner(c, dicts)
    inner(T, dicts)
    return dicts

def _all_slots(T):
    """ Return a list of all slots for a type, or object.

    Args:
        T: the type, or object to determine the slots for.

    Returns:
        The list of slot names, including those in base classes.
    """
    if not isinstance(T, type):
        T = type(T)
    slots = []
    def inner(T, slots):
        if hasattr(T, '__slots__'):
            slots += [s for s in T.__slots__]
        for c in T.__bases__:
            inner(c, slots)
    inner(T, slots)
    return slots

def attr_names(parent, child):
    """Return the attribute name(s) (in parent) for a child object.

    Args:
        parent: the parent object
        child: the child object

    Returns:
        A list of attribute names, in the parent, referencing the child
        object, or ['UNKNOWN'] if no names can be found for the child.
    """
    names = []
    if hasattr(parent, '__dict__') and child is parent.__dict__:
        names.append('__dict__')
    elif isinstance(parent, Set):
        for k, v in enumerate(parent):
            if id(v) == id(child):
                names.append(str(k))
    elif isinstance(parent, (tuple, list, deque)):
        for k, v in enumerate(parent):
            if id(v) == id(child):
                names.append(str(k))
    elif isinstance(parent, Mapping) or hasattr(parent, iteritems):
        for k, v in getattr(parent, iteritems)():
            if id(v) == id(child):
                names.append(str(k))
    for _dict in _all_dicts(parent):
        for k, v in _dict.items():
            if id(v) == id(child):
                names.append(str(k))
    for k in _all_slots(parent):
        if hasattr(parent, k):
            v = getattr(parent, k)
            if id(v) == id(child):
                names.append(str(k))
    if not names:
        names.append('<UNKNOWN>')
    return names

def sizeof(obj, verbose = False):
    """Get the size of an object instance and its unique attributes.

    The size returned is the size of the object, as returned by
    sys.getsizeof, plus the sizes of all unique attributes it contains,
    including:
        * the attriute dictionary, '__dict__'
        * the attributes referenced by '__dict__'
        * the key values stored by '__dict__'
        * the attributes referenced by '__slots__'

    If there aare multiple attributes referencing the same object, the
    referenced object is only counted once.

    Attributes that are not unique to the object are excluded from the
    size calculation, including references to:
        * modules
        * functions
        * classes
        * built-in objects
        * class attributes (except where overridden by the instance)

    Args:
        obj: the object to determine the size of
        verbose: A boolean, if True, print the attribute names and sizes
            of each attribute referenced by the object.

    Returns:
        The size of the object, including its unique attributes.
    """
    seen_ids = set(EXCLUDE_IDS)
    def inner(obj, level = 0, name = ''):
        obj_id = id(obj)
        if isinstance(obj, EXCLUDE_TYPES) or id(obj) in seen_ids:
            size = 0
        elif is_class_attr(obj, name):
            size = 0
        else:
            if verbose:
                print('%s%s %s: %r' % (' ' * level, obj_id, name, obj))
            seen_ids.add(obj_id)
            size = sys.getsizeof(obj)
            if isinstance(obj, zero_depth_bases):
                pass
            elif isinstance(obj, (tuple, list, Set, deque)):
                size += sum(inner(v, level + 1, '%s[%s]' % (name, k))
                            for k, v in enumerate(obj))
            elif isinstance(obj, Mapping) or hasattr(obj, iteritems):
                size += sum(inner(k, level + 1, '%s[%s]k' % (name, k)) +
                            inner(v, level + 1, '%s[%s]v' % (name, k))
                            for k, v in getattr(obj, iteritems)())
            # Check for custom object instances - may subclass above too
            for _dict in _all_dicts(obj):
                for k, v in _dict.items():
                    if not (isinstance(obj, EXCLUDE_TYPES) or
                            id(obj) in seen_ids or
                            # __slots__ are handled below
                            k == '__slots__'):
                        size += inner(k, level + 1, 'key: ' + k)
                        size += inner(v, level + 1, k)
            for k in _all_slots(obj):
                if hasattr(obj, k):
                    v = getattr(obj, k)
                    if not (isinstance(v, EXCLUDE_TYPES) or id(v) in seen_ids):
                        size += inner(v, level + 1, k)
            # Check referents, in case anything was missed.
            for o in get_referents(obj):
                if not (isinstance(o, EXCLUDE_TYPES) or id(o) in seen_ids):
                    k = '|'.join(attr_names(obj, o))
                    size += inner(o, level + 1, '(%s)' % (k,))
        if verbose:
            print('%s%s %d %s: %r' % (' ' * level, obj_id, size, name, obj))
        return size
    return inner(obj)
