export const GSS_C_MUTUAL_FLAG: number;
export const GSS_C_SEQUENCE_FLAG: number;
export const GSS_C_CONF_FLAG: number;
export const GSS_C_INTEG_FLAG: number;
export const GSS_MECH_OID_KRB5: number;
export const GSS_MECH_OID_SPNEGO: number;
export const LDAP_AXI_PATCH_LEVEL: 1;

export interface WrapOptions {
  protect?: boolean;
}

export interface InitializeClientOptions {
  flags?: number;
  mechOID?: number;
  channelBindingData?: Uint8Array;
}

export interface WrapResult {
  response: string;
  confidential: boolean;
  integrity: boolean;
}

export interface UnwrapResult {
  response: string;
  confidential: boolean;
  integrity: boolean;
}

export interface KerberosClient {
  readonly username?: string;
  readonly contextComplete?: boolean;
  readonly contextFlags?: number;
  step(challenge: string): Promise<string | null>;
  wrap(challenge: string, options?: WrapOptions): Promise<string>;
  wrapWithResult(challenge: string, options?: WrapOptions): Promise<WrapResult>;
  wrapSizeLimit(maxWrappedBytes: number, options?: WrapOptions): Promise<number>;
  unwrap(challenge: string): Promise<string>;
  unwrapWithResult(challenge: string): Promise<UnwrapResult>;
}

export function initializeClient(service: string, options?: InitializeClientOptions): Promise<KerberosClient>;
