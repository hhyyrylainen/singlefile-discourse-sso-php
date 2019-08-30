# Single file SSO client for [Discourse](https://github.com/discourse/discourse) in PHP (w/ PostgreSQL and logout)

Usage how to on Discourse Meta:

* [MediaWiki](https://meta.discourse.org/t/using-discourse-sso-with-mediawiki/69218)
* [MantisBT 1.2](https://meta.discourse.org/t/using-discourse-sso-with-mantis-bug-tracker/69236)

Related projects:

* [MantisDiscourseSSO](https://github.com/ArseniyShestakov/MantisDiscourseSSO) plugin repository


## Adding a logout link
Here's a sample thing to put in `LocalSettings.php`:

```php
# Logout for authentication
define('SSO_LOGOUT_TOKEN', hash('sha512', $SSO_STATUS["nonce"]));
$wgAuthRemoteuserUserUrls = [
    'logout' => function( $metadata ) {
        return '/discourse-sso.php?logout=' . SSO_LOGOUT_TOKEN;
    }
];
```
