---
layout: post
title:  "Sea of Quills - Web"
date:   2021-04-08 12:28:05 +0100
categories: writeups
---

```
Challenge: Sea of Quills 1 & 2
author: Shotokhan
Description: SQL injection filter bypass
CTF: angstromCTF 2021
Category: Web
```

# Writeup
It's clearly a SQL injection challenge, source code (Ruby) is provided and we can see that the query is built like that:
```
@row = db.execute("select %s from quills limit %s offset %s" % [cols, lim, off])
```
Where "cols", "lim" and "off" are user provided.
There is a regex match on the latter two parameters to ensure they are composed by digits.
We will assume that this regex match works properly and will focus on "cols" parameter.

In the first challenge, there was this blacklist for "cols":
```
["-", "/", ";", "'", "\""]
```
We know that underlying DB is sqlite3. Since connectors are used, we can't inject dot commands.
We can't do query stacking and we don't know how to comment out the rest of the query with these filters.
But we can make an UNION based injection and see the result, and we can also control the number of columns.

Let's build a payload:
```
cols: * from sqlite_master union select 0,0,0,0,0
limit: 100
offset: 0
```
We got the following result:

![tables](https://github.com/pwnthenope/pwnthenope.github.io/blob/main/static/post_images/sea_of_quills_tables.jpg?raw=true)

Now we know that there is a table called flagtable.
We don't know how many columns it has (we could get to know it from sqlite_master if we wanted), so let's start the union based injection with one column.
```
cols: * from flagtable union select 0
limit: 100
offset: 0
```
It turns out that flagtable has only one column, and we got the first flag:

![first_flag](https://github.com/pwnthenope/pwnthenope.github.io/blob/main/static/post_images/sea_of_quills_first_flag.jpg?raw=true)

Here it is: actf{and_i_was_doing_fine_but_as_you_came_in_i_watch_my_regex_rewrite_f53d98be5199ab7ff81668df}

Now, head to the second part.
The blacklist is enriched with the filter on "flag" keyword and there is a 24 characters limit on "cols" parameter.

The filter on the keyword is easily defeated, because it only uses lowercase characters:
```
* from fLaGtAbLe union select 0
```
But the length of this payload is 31, so we have to think at something else.

After many hours spent in researches and local tries in sqlite3 shell, I realized that it is legal to make a query like that:
```
select (select username from another_table) from users;
```
That is, you can specify a subquery as a column, with the constraint that this subquery returns only one column.
In our case, we can even use the asterisk because flagtable has only one column. Our new "cols" payload:
```
(select * from fLaGtAbLe)
```
Very close, this is 25 characters long.
We need to use another trick: the asterisk is a special character, so we can use it without whitespaces.
```
(select*from fLaGtAbLe)
```
With this payload, we managed to get the second flag:

![second_flag](https://github.com/pwnthenope/pwnthenope.github.io/blob/main/static/post_images/sea_of_quills_second_flag.jpg?raw=true)

Here it is: actf{the_time_we_have_spent_together_riding_through_this_english_denylist_c0776ee734497ca81cbd55ea}

The intended solution exploited the fact that, in Ruby, regex match stops at newline, and so it uses the following payload for both challenges:
```
cols: * FROM(select name,desc
limit: 1
offset: 1\n) UNION SELECT flag, 1 FROM flagtable
```
