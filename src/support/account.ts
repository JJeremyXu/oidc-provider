import { Provider } from 'oidc-provider';
import { nanoid } from 'nanoid';
import MongoAdapter from "../adapters/mongodb";
import { ObjectId } from 'mongodb';
const store = new Map();
const logins = new Map();
type User = {
  sub: string,
  [x: string]: string
}
export class Account {
  private accountId;
  constructor(id: any, private profile: any = {}) {
    this.accountId = id || nanoid();
    store.set(this.accountId, this);
  }

  /**
   * @param use - can either be "id_token" or "userinfo", depending on
   *   where the specific claims are intended to be put in.
   * @param scope - the intended scope, while oidc-provider will mask
   *   claims depending on the scope automatically you might want to skip
   *   loading some claims from external resources etc. based on this detail
   *   or not return them in id tokens but only userinfo and so on.
   */
  async claims(use: any, scope: any) { // eslint-disable-line no-unused-vars
    if (this.profile) {
      return {
        sub: this.accountId, // it is essential to always return a sub claim
        email: this.profile.email,
        email_verified: this.profile.email_verified,
        family_name: this.profile.family_name,
        given_name: this.profile.given_name,
        locale: this.profile.locale,
        name: this.profile.name,
      };
    }

    return {
      sub: this.accountId, // it is essential to always return a sub claim

      address: {
        country: '000',
        formatted: '000',
        locality: '000',
        postal_code: '000',
        region: '000',
        street_address: '000',
      },
      birthdate: '1987-10-16',
      email: 'johndoe@example.com',
      email_verified: false,
      family_name: 'Doe',
      gender: 'male',
      given_name: 'John',
      locale: 'en-US',
      middle_name: 'Middle',
      name: 'John Doe',
      nickname: 'Johny',
      phone_number: '+49 000 000000',
      phone_number_verified: false,
      picture: 'http://lorempixel.com/400/200/',
      preferred_username: 'johnny',
      profile: 'https://johnswebsite.com',
      updated_at: 1454704946,
      website: 'http://example.com',
      zoneinfo: 'Europe/Berlin',
    };
  }

  static async findByFederated(provider: Provider, claims: any) {
    const id = `${provider}.${claims.sub}`;
    if (!logins.get(id)) {
      logins.set(id, new Account(id, claims));
    }
    return logins.get(id);
  }

  static async findByLogin(login: any) {
    if (!logins.get(login)) {
      logins.set(login, new Account(login));
    }

    return logins.get(login);
  }

  // static async findAccount(ctx: any, id: any, token: any) { // eslint-disable-line no-unused-vars
  //   // token is a reference to the token used for which a given account is being loaded,
  //   //   it is undefined in scenarios where account claims are returned from authorization endpoint
  //   // ctx is the koa request context
  //   if (!store.get(id)) new Account(id); // eslint-disable-line no-new
  //   return store.get(id);
  // }

  static async findAccount(ctx: any, id: string, token: any) {
    console.log("token", token);
    console.log("findAccount => ", id);
    return {
      accountId: id,
      async claims(use: any, scopes: string) {
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
  }
}

