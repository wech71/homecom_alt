# homecom-alt

Python wrapper for controlling devices managed by MyBuderus App.

This is a fork of https://github.com/serbanb11/homecom_alt with changes to connect to Buderus devices like MX300/MX400 with setup instructions from https://github.com/serbanb11/bosch-homecom-hass

### Step-by-Step Instructions to get the necessary code for example.py

#### 1. Open the Authorization URL

Open the following URL in your browser:

```
https://singlekey-id.com/auth/connect/authorize?state=nKqS17oMAxqUsQpMznajIr&nonce=5yPvyTqMS3iPb4c8RfGJg1&code_challenge=Fc6eY3uMBJkFqa4VqcULuLuKC5Do70XMw7oa_Pxafw0&redirect_uri=com.buderus.tt.dashtt://app/login&client_id=762162C0-FA2D-4540-AE66-6489F189FADC&response_type=code&prompt=login&scope=openid+email+profile+offline_access+pointt.gateway.claiming+pointt.gateway.removal+pointt.gateway.list+pointt.gateway.users+pointt.gateway.resource.dashapp+pointt.castt.flow.token-exchange+bacon+hcc.tariff.read&code_challenge_method=S256&style_id=tt_bud
```

---

#### 2. Open Developer Tools (Network Tab)

- Press `F12` or right-click > **Inspect**.
- Go to the **Network** tab.

![Developer Tools](./img/dev_tools.png)

---

#### 3. Log In Using Your Credentials

- Enter your **username and password** on the loaded page.
- Complete any CAPTCHA if required.
- Wait for the login to complete and redirect.

> You may see a redirect error due to unsupported URI scheme (`com.bosch.tt.dashtt.pointt://...`). This is expected.

---

#### 4. Extract the Authorization Code

- In the **Network tab**, find the request to the redirect URI:
  ```
  com.bosch.tt.dashtt.pointt://app/login?code=YOUR_CODE_HERE&state=...
  ```
- Copy only the value of the `code` parameter. This values should end in **-1**

  Example:
  ```
  code=3d7a2ff1f39e4d509e83012b45e7abcd-1
  ```

![Authorization Code](./img/login.png)

---

## How to use package
[Check example.py](example.py)
