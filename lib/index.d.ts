// Type definitions for krs-service-pricing
// Project: krs-service-pricing
// Definitions by: Sasa Djolic <https://www.linkedin.com/in/sasadjolic/>

import * as express from 'express'

export interface Credentials {
    scheme: string;
    claims: string[];
}

export interface ValidationFunction {
    (credentials: Credentials): Credentials;
}

export interface ReissuanceFunction {
    (credentials: Credentials): Credentials;
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
