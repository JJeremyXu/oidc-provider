import { Configuration } from "oidc-provider";
import MongoAdapter from "../adapters/mongodb";
import { Collection, Db, MongoClient, ObjectId } from 'mongodb';
import e from "express";

type User = {
  sub: string,
  [x: string]: string
}

export const configuration : Configuration = {
    adapter: MongoAdapter,
    clientBasedCORS(ctx, origin, client) {
      return true;
    },
    clients: [
      {
        client_id: "foo",
        client_secret: "bar",
        redirect_uris: [
          "https://jwt.io",
          "https://openidconnect.net/callback",
          "https://oauth.pstmn.io/v1/callback",
          "https://oauthdebugger.com/debug",
          "https://oidcdebugger.com/debug",
          "http://localhost:3000/api/auth/callback/orosound"
        ], // using jwt.io as redirect_uri to show the ID Token contents
        // response_types: ['code id_token'],
        // grant_types: ['authorization_code', 'implicit'],
        // response_types: ["id_token", "code", "code id_token"],
        // grant_types: ["implicit", "authorization_code", "refresh_token"],
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ['code'],
        scope: "openid email profile phone address offline_access",
        // scope: "openid email profile address",
        application_type: "web",
      },
    ],

    // Openid Standard Claims: https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
    claims: {
      address: ["address"],
      email: ["email", "email_verified"],
      phone: ["phone_number", "phone_number_verified"],
      profile: [
        "birthdate",
        "family_name",
        "gender",
        "given_name",
        "locale",
        "middle_name",
        "name",
        "nickname",
        "picture",
        "preferred_username",
        "profile",
        "updated_at",
        "website",
        "zoneinfo",
      ],
    },

    // Openid Standard Claims: https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims

    cookies: {
      keys: "SuperSecret".split(","),
    },
    interactions: {
      url(ctx, interaction) {
        return `/interaction/${interaction.uid}`;
      },
    },

    //not figure out yet
    features: {
      // disable the packaged interactions
      devInteractions: { enabled: false },
      introspection: {
        enabled: true,
        allowedPolicy(ctx, client, token) {
          if (
            client.introspectionEndpointAuthMethod === "none" &&
            token.clientId !== ctx.oidc.client?.clientId
          ) {
            return false;
          }
          return true;
        },
      },
      resourceIndicators: {
        defaultResource(ctx) {
          console.log("ctx.oidc.params => ",ctx.oidc.params)
          return Array.isArray(ctx.oidc.params?.resource)
            ? ctx.oidc.params?.resource[0]
            : ctx.oidc.params?.resource;
        },
        getResourceServerInfo(ctx, resourceIndicator, client) {
          return {
            scope: "api:read offline_access",
          };
        },
      },
    },
    pkce: {
      methods: ["S256", "plain"],
      required: function pkceRequired(ctx, client) {
        return false;
      },
    },
    jwks: {
      keys: [
        {
          kty: "RSA",
          n: "jw3bixcae4ktBdXYcKeK5J7pmsXvQdvuOB8yv_q426tsMDlTZ1jj9CgYEZF_SCfzwQ5pcogLD-WY-LYJtt8zfjU_mWZZWcbR1QcMIWhLsSdi2OSlksIewMiv5CzvDBzs6h9sU0yr6yY6SYmT89jXU-D0MqSakDR0x0tyVUonGAWiVGJYINCCEbonoqFYAXjKdrNCCIliXiWQS6rajkEEXj0I2uQr4L1S80mSWWvDfFmFw4yC7V9nOGf1OPotscLCpT7vzlhHCuh3rY12bTEceZeARQ9G9aWQMBhQZPIPBvLdTRl5smFByFJ_FWs2yXXdHXFRo2L8UgwV2D4qVlgUXw",
          e: "AQAB",
          d: "PodKHUPd-X1-RnywfJ1fIosrhNFbwSfGupU4c529y5bkVTfZcuTxzrjvvE4imoGMFCiegsdgPnSXJq87E8oAEfxobj7Ec29qLHlGHhweabLTjAZ1MO7UzmNqLoxNeLfz_mn5yXdL9h7hf185Ym63wBwl4TT9smabXLlnokwlRmQXL-FWN5P50X60XgPG9hbv5BGPCrfbNNkLzae3fVeTfAZUYw-rwfrKN_HVUz78lo3cNhE2AVMnIF2CeZeH1xrUC81MWGJi7W1R1MtMTUObdqCpqLMtoWSojF3UT0pOMCiMeEt25EGpMiRVNy8HQD-z92uBEh8n2DYWb8Fou1Wa0Q",
          p: "23oJTOlWauw_fQJxBmwkfzPL_j9p_Fjtf_ThESn4ZpCkl2Y5cKSqc70bBP3SkgKRWWIt8QunkmkSHDmVzu0_UQu7YgCxqwwR8TvK8uCgNw8umtE_2w2fvf8l_863TEg4btz87kMtk01vWRUcqQxlBvd-bTmL8FDm0iblkskSpbs",
          q: "ptwhZzh1TkXFiglDz04_dC6s-Ek_qRxTtUSdhaRr7UDzpa_mEEd41m3kgmjgIlK-FgDpf66N4OWHQow76PVtRUAQSZDSPo4k8TNs5AY_oyzIBAWBnakfs8L368Vo4O3RZJ4wiMqnphTRGiM6rLOev74uTILcVnPgDZLbAm2Gb60",
          dp: "QDjIienpcKYqucDCI_f3AgW9Fmul7sJy1LNqPGSEnDaNAwRVoIF-oxld06sWN8VqlLYm7VbUtQHr27h5_q_rjCKbtUSwuHVytp0heMqD9ziJEaJTRh0JdkY370-k0Tx8zuv5UxrzNhw9jdqgpVLMKSq4outo6Gwz7qCVIsuVmks",
          dq: "FHPNAFryPfrdYLMMBcAAlRwXhYNs8yyOshxL9pKVzAn3E2sBFyO7kwT7SmTSfEKKHCZWeJkLuPJJZwXLXh2fHCrjFDFVI-fGbW4xPa3qZPTbO2r1XT7arO0L-HFFDrT3wo6FQm8cp4XLr5l72qlVnwkPob80hMBFSUSj5aNJJC0",
          qi: "MJJ6KTrCdq1gEgH-MpDF4DeXhE_dlB1P2am3juUR8ieZmohWbruBo6vmA_9Fm_lUs6V3qZ7gjbszguQZwcIFnvXceOBMH35_8TQLM3IrnNTJJTyWslrH3rdLAsIPk_x0cgIJ_gC0BHiQ9TfW8mKjGAK0JRv-V8XXnT4ZFQrlmQI",
        },
      ],
    },
    // Expirations for various token and session types. The value can be a number (in seconds) or a synchronous function that dynamically returns value based on the context.
    ttl: {
      AccessToken: function AccessTokenTTL(ctx, token, client) {
        if (token.resourceServer) {
          return token.resourceServer.accessTokenTTL || 60 * 60; // 1 hour in seconds
        }
        return 60 * 60; // 1 hour in seconds
      },
      AuthorizationCode: 600 /* 10 minutes in seconds */,
      BackchannelAuthenticationRequest:
        function BackchannelAuthenticationRequestTTL(ctx, request, client) {
          if (ctx.oidc.params) {
            if (ctx && ctx.oidc && ctx.oidc.params.requested_expiry) {
              return Math.min(
                10 * 60,
                +(ctx.oidc.params.requested_expiry as Number)
              ); // 10 minutes in seconds or requested_expiry, whichever is shorter
            }
          }
  
          return 10 * 60; // 10 minutes in seconds
        },
      ClientCredentials: function ClientCredentialsTTL(ctx, token, client) {
        if (token.resourceServer) {
          return token.resourceServer.accessTokenTTL || 10 * 60; // 10 minutes in seconds
        }
        return 10 * 60; // 10 minutes in seconds
      },
      DeviceCode: 600 /* 10 minutes in seconds */,
      Grant: 1209600 /* 14 days in seconds */,
      IdToken: 3600 /* 1 hour in seconds */,
      Interaction: 3600 /* 1 hour in seconds */,
      RefreshToken: function RefreshTokenTTL(ctx, token, client) {
        if (
          ctx &&
          ctx.oidc.entities.RotatedRefreshToken &&
          client.applicationType === "web" &&
          client.tokenEndpointAuthMethod === "none" &&
          !token.isSenderConstrained()
        ) {
          // Non-Sender Constrained SPA RefreshTokens do not have infinite expiration through rotation
          return ctx.oidc.entities.RotatedRefreshToken.remainingTTL;
        }
  
        return 14 * 24 * 60 * 60; // 14 days in seconds
      },
      Session: 1209600,
    },

    /**
     * Calculates the square root of a number.
     *
     * @param id object id(mongodb)
     * @returns the square root if `x` is non-negative or `NaN` if `x` is negative.
     */
    async findAccount(ctx: any, id: string, token: any) {
      console.log("token", token);
      console.log("findAccount => ", id);
      return {
        accountId: id,
        async claims(use, scopes) {

          console.log("use",use);
            //define what we want others use access_token to get our resourse.
          const user = await MongoAdapter.coll('users').findOne({_id: new ObjectId(id)});
          const data : User = {
            sub: id,
          }
          scopes.split(' ').forEach(scope => { 
            data[scope] = user![scope];
          })
          console.log(scopes.split(" "));
          console.log(data);
          // return { sub: id, email: data!.email||"NO EMAIL PROVI DED"};
          return data;
        },
      };
    },
    // async issueRefreshToken(ctx, client, code) {
    //   console.log("issueRefreshToken")
    //   console.log("code => ", code.scopes)
    //   return client.grantTypeAllowed('refresh_token') && code.scopes.has('offline_access');
    // },
    async issueRefreshToken(ctx, client, code) {
      console.log("issueRefreshToken");
      console.log("code => ", code)
      console.log("scope => ", code.scopes)
      console.log("client.tokenEndpointAuthMethod => ", client.tokenEndpointAuthMethod)
      console.log("client.applicationType => ", client.applicationType)
      if (!client.grantTypeAllowed("refresh_token")) {
        return false;
      }
      console.log(code.scopes.has("offline_access") ||
      (client.applicationType === "web" &&
        client.tokenEndpointAuthMethod === "none"))
      return (
        code.scopes.has("offline_access") ||
        (client.applicationType === "web")
      );
    },
    tokenEndpointAuthMethods: [
      "client_secret_basic",
      "client_secret_jwt",
      "client_secret_post",
      "private_key_jwt",
      "none"
    ],
}
