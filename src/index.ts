import "dotenv/config";
import { Provider } from "oidc-provider";
import express, { Express } from "express";
import path from "path";
import bodyParser from "body-parser";
import assert from "assert";
import MongoAdapter from "./adapters/mongodb";
import { configuration } from "./support/configuration";

const app: Express = express();
const parse = bodyParser.urlencoded({ extended: false });
MongoAdapter.connect();
const oidc = new Provider("http://localhost:8000", configuration);

//http://localhost:8000/auth?client_id=foo&response_type=code&redirect_uri=https%3A%2F%2Fjwt.io&scope=openid%20email%20profile&nonce=foobar&prompt=login
// http://localhost:8000/auth?response_type=code%20id_token&client_id=foo&redirect_uri=https%3A%2F%2Fjwt.io&nonce=test&scope=openid
// http://localhost:8000/auth?response_type=code%20id_token&client_id=foo&redirect_uri=https%3A%2F%2Fjwt.io&nonce=test&scope=openid%20email%20profile
// http://localhost:8000/auth?response_type=id_token&client_id=foo&redirect_uri=https%3A%2F%2Fjwt.io&nonce=test&scope=openid%20email%20profile
// http://localhost:8000/auth?response_type=id_token&client_id=foa&redirect_uri=https%3A%2F%2Fjwt.io&nonce=test&scope=openid

app.set("view engine", "ejs");
app.set("views", path.resolve(__dirname, "views"));

function setNoCache(req: any, res: any, next: any) {
  res.set("Pragma", "no-cache");
  res.set("Cache-Control", "no-cache, no-store");
  next();
}

app.get("/interaction/:uid", setNoCache, async (req, res, next) => {
  try {
    const details = await oidc.interactionDetails(req, res);
    console.log(
      "see what else is available to you for interaction views",
      details
    );
    const { uid, prompt, params } = details;
    const client = await oidc.Client.find(params.client_id as string);
    console.log("params before login => ",params);

    if (prompt.name === "login") {
      return res.render("login", {
        client,
        uid,
        details: prompt.details,
        params,
        title: "Sign-in",
        flash: undefined,
      });
    }
    console.log(prompt.name, " => ");
    console.log(params);
    return res.render("interaction", {
      client,
      uid,
      details: prompt.details,
      params,
      title: "Authorize",
    });
  } catch (err) {
    return next(err);
  }
});

app.post(
  "/interaction/:uid/login",
  setNoCache,
  parse,
  async (req, res, next) => {
    try {
      const { uid, prompt, params } = await oidc.interactionDetails(req, res);
      assert.strictEqual(prompt.name, "login");
      const client = await oidc.Client.find(params.client_id as string);
      let accountId;
      let loginResult = await MongoAdapter.login(
        req.body.email,
        req.body.password
      );
      if (loginResult) {
        accountId = loginResult._id.toString();
      }

      if (!accountId) {
        res.render("login", {
          client,
          uid,
          details: prompt.details,
          params: {
            ...params,
            login_hint: req.body.email,
          },
          title: "Sign-in",
          flash: "Invalid email or password.",
        });
        return;
      }

      const result = {
        login: { accountId },
      };

      await oidc.interactionFinished(req, res, result, {
        mergeWithLastSubmission: false,
      });
    } catch (err) {
      next(err);
    }
  }
);

app.post(
  "/interaction/:uid/confirm",
  setNoCache,
  parse,
  async (req, res, next) => {
    try {
      const interactionDetails = await oidc.interactionDetails(req, res);
      const {
        prompt: { name, details },
        params,
        session,
      } = interactionDetails;

      const accountId = session?.accountId;
      assert.strictEqual(name, "consent");

      let { grantId } = interactionDetails;
      let grant;

      if (grantId) {
        // we'll be modifying existing grant in existing session
        grant = await oidc.Grant.find(grantId);
      } else {
        // we're establishing a new grant
        grant = new oidc.Grant({
          accountId,
          clientId: params.client_id as string,
        });
      }

      const missingOIDCScope = details.missingOIDCScope as string[];
      if (missingOIDCScope) {
        grant?.addOIDCScope(missingOIDCScope.join(" "));
        // use grant.rejectOIDCScope to reject a subset or the whole thing
      }
      if (details.missingOIDCClaims) {
        grant?.addOIDCClaims(details.missingOIDCClaims as string[]);
        // use grant.rejectOIDCClaims to reject a subset or the whole thing
      }
      if (details.missingResourceScopes) {
        // eslint-disable-next-line no-restricted-syntax
        for (const [indicator, scopes] of Object.entries(
          details.missingResourceScopes as any
        )) {
          grant?.addResourceScope(indicator, (scopes as string[]).join(" "));
          // use grant.rejectResourceScope to reject a subset or the whole thing
        }
      }

      grantId = await grant?.save();

      const consent: any = {};
      if (!interactionDetails.grantId) {
        // we don't have to pass grantId to consent, we're just modifying existing one
        consent.grantId = grantId;
      }

      const result = { consent };
      await oidc.interactionFinished(req, res, result, {
        mergeWithLastSubmission: true,
      });
    } catch (err) {
      next(err);
    }
  }
);

app.get("/interaction/:uid/abort", setNoCache, async (req, res, next) => {
  try {
    const result = {
      error: "access_denied",
      error_description: "End-User aborted interaction",
    };
    await oidc.interactionFinished(req, res, result, {
      mergeWithLastSubmission: false,
    });
  } catch (err) {
    next(err);
  }
});

app.use(oidc.callback());

app.listen(process.env.PORT || 8000, () => {
  console.log(
    "oidc-provider listening on port process.env.PORT, check http://localhost:8000/.well-known/openid-configuration"
  );
});
