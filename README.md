# SLC - Simple (or stupid) linux containers

Read a few blogposts, glued everything together.

Features
- Build and run a command in a linux container.
- Specify your own image source using a *cdef* (container definition) file

Why you should not use this
- No network separation
- Not safe whatsoever
- No cached build steps
- Probably full of bugs and unexpected behaviour

Why you should use this
- CONTAINERS!!

## Example

    sudo -E ./main.py run alpine.cdef pstree