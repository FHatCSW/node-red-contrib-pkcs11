## Step 1: Update Package Version
Before publishing a new version of your package, make sure to update the package version in your package.json file. You can use the following command to update the version:

```bash
npm version <new_version>
```

## Step 2: Log In to npm
If you haven't already logged in to your npm account, use the following command to log in:

```bash
npm login
```
Enter your npm username, password, and email address when prompted.

## Step 3: Publish Your Package
Use the following command to publish your Node-RED package to the npm registry:

``` bash
npm publish
```
