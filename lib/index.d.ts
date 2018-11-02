// Type definitions for @sasadjolic/express-authenticated
// Project: @sasadjolic/express-authenticated
// Definitions by: Sasa Djolic <https://www.linkedin.com/in/sasadjolic/>

import * as express from 'express'

export interface Credentials {
    scheme: string;
    claims: string[];
}

export interface ValidationFunction {
    (credentials: Credentials): Credentials | undefined | null | Promise<Credentials | undefined | null>;
}

export interface ReissuanceFunction {
    (credentials: Credentials): Credentials | Promise<Credentials>;
}

export interface AuthenticatorOptions {
    accept: string[],
    issuer: string,
    secret: string,
    validate: ValidationFunction,
    reissue: ReissuanceFunction
}

export class Authenticator {
    public constructor(options: AuthenticatorOptions)
    public authenticate(): express.RequestHandler
    public authenticated(): express.RequestHandler
    public authorized(filter: express.Router): express.RequestHandler
}
