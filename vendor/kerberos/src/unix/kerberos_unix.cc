#include <memory>

#include "../kerberos.h"
#include "../kerberos_worker.h"

namespace node_kerberos {

using namespace Napi;

static Napi::Object native_error(Napi::Env env, const gss_result& result) {
    auto error = Error::New(env, result.message).Value();
    error.Set("gssMajor", Number::New(env, result.major_status));
    error.Set("gssMinor", Number::New(env, result.minor_status));
    return error;
}

#define GSS_MECH_OID_KRB5 9
#define GSS_MECH_OID_SPNEGO 6

static char krb5_mech_oid_bytes[] = "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02";
gss_OID_desc krb5_mech_oid = {9, &krb5_mech_oid_bytes};

static char spnego_mech_oid_bytes[] = "\x2b\x06\x01\x05\x05\x02";
gss_OID_desc spnego_mech_oid = {6, &spnego_mech_oid_bytes};

/// KerberosClient
void KerberosClient::Step(const CallbackInfo& info) {
    auto state = this->state();
    std::string challenge = info[0].ToString();
    Function callback = info[1].As<Function>();

    KerberosWorker::Run(callback, "kerberos:ClientStep", [=](KerberosWorker::SetOnFinishedHandler onFinished) {
        gss_result result =
            authenticate_gss_client_step(state.get(), challenge.c_str());

        return onFinished([=](KerberosWorker* worker) {
            Napi::Env env = worker->Env();
            if (result.code == AUTH_GSS_ERROR) {
                worker->Call(std::initializer_list<napi_value>
                    { native_error(env, result), env.Null() });
                return;
            }

            Napi::Value response = env.Null();
            if (state->response != nullptr) {
                response = String::New(env, state->response);
            }

            worker->Call(std::initializer_list<napi_value>
                { env.Null(), response });
        });
    });
}

void KerberosClient::UnwrapData(const CallbackInfo& info) {
    auto state = this->state();
    std::string challenge = info[0].ToString();
    Function callback = info[1].As<Function>();

    KerberosWorker::Run(callback, "kerberos:ClientUnwrap", [=](KerberosWorker::SetOnFinishedHandler onFinished) {
        gss_result result =
            authenticate_gss_client_unwrap(state.get(), challenge.c_str());

        return onFinished([=](KerberosWorker* worker) {
            Napi::Env env = worker->Env();
            if (result.code == AUTH_GSS_ERROR) {
                worker->Call(std::initializer_list<napi_value>
                    { native_error(env, result), env.Null() });
                return;
            }

            worker->Call(std::initializer_list<napi_value>
                { env.Null(), String::New(env, state->response) });
        });
    });
}

void KerberosClient::UnwrapDataWithResult(const CallbackInfo& info) {
    auto state = this->state();
    std::string challenge = info[0].ToString();
    Function callback = info[1].As<Function>();

    KerberosWorker::Run(callback, "kerberos:ClientUnwrapWithResult", [=](KerberosWorker::SetOnFinishedHandler onFinished) {
        gss_result result = authenticate_gss_client_unwrap(state.get(), challenge.c_str());

        return onFinished([=](KerberosWorker* worker) {
            Napi::Env env = worker->Env();
            if (result.code == AUTH_GSS_ERROR) {
                worker->Call(std::initializer_list<napi_value>
                    { native_error(env, result), env.Null() });
                return;
            }

            Object unwrapped = Object::New(env);
            unwrapped.Set("response", String::New(env, state->response ? state->response : ""));
            unwrapped.Set("confidential", Boolean::New(env, result.confidentiality));
            unwrapped.Set("integrity", Boolean::New(env, result.integrity));
            worker->Call(std::initializer_list<napi_value>{ env.Null(), unwrapped });
        });
    });
}

void KerberosClient::WrapSizeLimit(const CallbackInfo& info) {
    auto state = this->state();
    uint32_t max_output_size = info[0].As<Number>().Uint32Value();
    Object options = info[1].ToObject();
    Function callback = info[2].As<Function>();
    int protect = ParseWrapOptionsProtect(options);

    KerberosWorker::Run(callback, "kerberos:ClientWrapSizeLimit", [=](KerberosWorker::SetOnFinishedHandler onFinished) {
        OM_uint32 max_input_size = 0;
        gss_result result = authenticate_gss_client_wrap_size_limit(state.get(), max_output_size, protect, &max_input_size);
        return onFinished([=](KerberosWorker* worker) {
            Napi::Env env = worker->Env();
            if (result.code == AUTH_GSS_ERROR) {
                worker->Call(std::initializer_list<napi_value>{ native_error(env, result), env.Null() });
                return;
            }
            worker->Call(std::initializer_list<napi_value>{ env.Null(), Number::New(env, max_input_size) });
        });
    });
}

void KerberosClient::WrapData(const CallbackInfo& info) {
    WrapDataInternal(info, false);
}

void KerberosClient::WrapDataWithResult(const CallbackInfo& info) {
    WrapDataInternal(info, true);
}

void KerberosClient::WrapDataInternal(const CallbackInfo& info, bool detailed) {
    auto state = this->state();
    std::string challenge = info[0].ToString();
    Object options = info[1].ToObject();
    Function callback = info[2].As<Function>();
    std::string user = ToStringWithNonStringAsEmpty(options["user"]);
    int protect = ParseWrapOptionsProtect(options);

    KerberosWorker::Run(callback, "kerberos:ClientWrap", [=](KerberosWorker::SetOnFinishedHandler onFinished) {
        gss_result result = detailed
            ? authenticate_gss_client_wrap_data(state.get(), challenge.c_str(), protect)
            : authenticate_gss_client_wrap_selection(
                state.get(), challenge.c_str(), user.c_str(), protect);

        return onFinished([=](KerberosWorker* worker) {
            Napi::Env env = worker->Env();
            if (result.code == AUTH_GSS_ERROR) {
                worker->Call(std::initializer_list<napi_value>
                    { native_error(env, result), env.Null() });
                return;
            }

            if (detailed) {
                Object wrapped = Object::New(env);
                wrapped.Set("response", String::New(env, state->response));
                wrapped.Set("confidential", Boolean::New(env, result.confidentiality));
                wrapped.Set("integrity", Boolean::New(env, result.integrity));
                worker->Call(std::initializer_list<napi_value>{ env.Null(), wrapped });
            } else {
                worker->Call(std::initializer_list<napi_value>
                    { env.Null(), String::New(env, state->response) });
            }
        });
    });
}

/// KerberosServer
void KerberosServer::Step(const CallbackInfo& info) {
    auto state = this->state();
    std::string challenge = info[0].ToString();
    Function callback = info[1].As<Function>();

    KerberosWorker::Run(callback, "kerberos:ServerStep", [=](KerberosWorker::SetOnFinishedHandler onFinished) {
        gss_result result =
            authenticate_gss_server_step(state.get(), challenge.c_str());

        return onFinished([=](KerberosWorker* worker) {
            Napi::Env env = worker->Env();
            if (result.code == AUTH_GSS_ERROR) {
                worker->Call(std::initializer_list<napi_value>
                    { native_error(env, result), env.Null() });
                return;
            }

            Napi::Value response = env.Null();
            if (state->response != nullptr) {
                response = String::New(env, state->response);
            }

            worker->Call(std::initializer_list<napi_value>
                { env.Null(), response });
        });
    });
}

/// Global Methods
void InitializeClient(const CallbackInfo& info) {
    std::string service = info[0].ToString();
    Object options = info[1].ToObject();
    Function callback = info[2].As<Function>();

    std::string principal = ToStringWithNonStringAsEmpty(options["principal"]);
    const ChannelBindingInput channel_bindings = read_channel_binding_input(options);
    Value flags_v = options["flags"];
    uint32_t gss_flags = flags_v.IsNumber() ? flags_v.As<Number>().Uint32Value() : GSS_C_MUTUAL_FLAG|GSS_C_SEQUENCE_FLAG;
    Value mech_oid_v = options["mechOID"];
    uint32_t mech_oid_int = mech_oid_v.IsNumber() ? mech_oid_v.As<Number>().Uint32Value() : 0;
    gss_OID mech_oid = GSS_C_NO_OID;
    if (mech_oid_int == GSS_MECH_OID_KRB5) {
        mech_oid = &krb5_mech_oid;
    } else if (mech_oid_int == GSS_MECH_OID_SPNEGO) {
        mech_oid = &spnego_mech_oid;
    }

    KerberosWorker::Run(callback, "kerberos:InitializeClient", [=](KerberosWorker::SetOnFinishedHandler onFinished) {
        auto client_state = std::make_shared<gss_client_state>();
        client_state->channel_bindings_present = channel_bindings.supplied;
        client_state->channel_binding_data = channel_bindings.data;
        gss_result result = authenticate_gss_client_init(
            service.c_str(), principal.c_str(), gss_flags, NULL, mech_oid, client_state.get());

        return onFinished([=](KerberosWorker* worker) {
            Napi::Env env = worker->Env();
            if (result.code == AUTH_GSS_ERROR) {
                worker->Call(std::initializer_list<napi_value>
                    { native_error(env, result), env.Null() });
                return;
            }

            worker->Call(std::initializer_list<napi_value>
                { env.Null(), KerberosClient::NewInstance(env, std::move(client_state)) });
        });
    });
}

void InitializeServer(const CallbackInfo& info) {
    std::string service = info[0].ToString();
    Function callback = info[1].As<Function>();

    KerberosWorker::Run(callback, "kerberos:InitializeServer", [=](KerberosWorker::SetOnFinishedHandler onFinished) {
        auto server_state = std::make_shared<gss_server_state>();
        gss_result result =
            authenticate_gss_server_init(service.c_str(), server_state.get());

        return onFinished([=](KerberosWorker* worker) {
            Napi::Env env = worker->Env();
            if (result.code == AUTH_GSS_ERROR) {
                worker->Call(std::initializer_list<napi_value>
                    { native_error(env, result), env.Null() });
                return;
            }

            worker->Call(std::initializer_list<napi_value>
                { env.Null(), KerberosServer::NewInstance(env, std::move(server_state)) });
        });
    });
}

void PrincipalDetails(const CallbackInfo& info) {
    std::string service = info[0].ToString();
    std::string hostname = info[1].ToString();
    Function callback = info[2].As<Function>();

    KerberosWorker::Run(callback, "kerberos:PrincipalDetails", [=](KerberosWorker::SetOnFinishedHandler onFinished) {
        gss_result result =
            server_principal_details(service.c_str(), hostname.c_str());

        return onFinished([=](KerberosWorker* worker) {
            Napi::Env env = worker->Env();
            if (result.code == AUTH_GSS_ERROR) {
                worker->Call(std::initializer_list<napi_value>
                    { native_error(env, result), env.Null() });
                return;
            }

            worker->Call(std::initializer_list<napi_value>
                { env.Null(), String::New(env, result.data) });
        });
    });
}

void CheckPassword(const CallbackInfo& info) {
    std::string username = info[0].ToString();
    std::string password = info[1].ToString();
    std::string service = info[2].ToString();

    std::string defaultRealm;
    Function callback;
    if (info[3].IsFunction()) {
        callback = info[3].As<Function>();
    } else {
        defaultRealm = info[3].ToString();
        callback = info[4].As<Function>();
    }

    KerberosWorker::Run(callback, "kerberos:CheckPassword", [=](KerberosWorker::SetOnFinishedHandler onFinished) {
        gss_result result = authenticate_user_krb5pwd(
            username.c_str(), password.c_str(), service.c_str(), defaultRealm.c_str());

        return onFinished([=](KerberosWorker* worker) {
            Napi::Env env = worker->Env();
            if (result.code == AUTH_GSS_ERROR) {
                worker->Call(std::initializer_list<napi_value>
                    { native_error(env, result), env.Null() });
            } else {
                worker->Call(std::initializer_list<napi_value>
                    { env.Null(), env.Null() });
            }
        });
    });
}

}
