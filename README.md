# Temporal Side Channel Attack

This code demonstrates temporal side channel attack on the server at http://aoi.ise.bgu.ac.il/ as part of the "Attacks on Implementations of Secure Systems" class by Dr. Yossi Oren @BGU, spring 2021.

The server responds with '1' on correct password, '0' otherwise. The mission is to reveal the password by exploiting the temporal side channel intoduced by the sever. Every username is valid.

## How to Run?

```python3 aoi_ass1.py [username]```

For example:
```python3 aoi_ass1.py chendoy```

