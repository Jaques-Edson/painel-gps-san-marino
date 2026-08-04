import { createClient } from "npm:@supabase/supabase-js@2";

const ADMIN_EMAIL = "edson@sanmarinofiat.com.br";
const ALLOWED_ORIGINS = new Set([
  "https://jaques-edson.github.io",
  "http://127.0.0.1:8765",
  "http://localhost:8765",
]);

function corsHeaders(req: Request) {
  const origin = req.headers.get("origin") || "";
  return {
    "Access-Control-Allow-Origin": ALLOWED_ORIGINS.has(origin) ? origin : "https://jaques-edson.github.io",
    "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Vary": "Origin",
  };
}

function json(req: Request, body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders(req), "Content-Type": "application/json; charset=utf-8" },
  });
}

function requiredString(value: unknown, name: string) {
  const result = String(value || "").trim();
  if (!result) throw new Error(`Informe ${name}.`);
  return result;
}

function profileRole(role: unknown) {
  return role === "manager" ? "manager" : "operator";
}

function publicRole(role: unknown) {
  return role === "operator" ? "evaluator" : String(role || "evaluator");
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders(req) });
  if (req.method !== "POST") return json(req, { error: "Metodo nao permitido." }, 405);

  try {
    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    if (!supabaseUrl || !serviceRoleKey) throw new Error("Funcao administrativa sem configuracao do Supabase.");

    const authorization = req.headers.get("authorization") || "";
    const token = authorization.replace(/^Bearer\s+/i, "");
    if (!token) return json(req, { error: "Sessao obrigatoria." }, 401);

    const admin = createClient(supabaseUrl, serviceRoleKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });
    const { data: callerData, error: callerError } = await admin.auth.getUser(token);
    const callerEmail = String(callerData.user?.email || "").toLowerCase();
    if (callerError || !callerData.user) return json(req, { error: "Sessao invalida ou expirada." }, 401);
    if (callerEmail !== ADMIN_EMAIL) return json(req, { error: "Acesso exclusivo do administrador." }, 403);

    const body = await req.json();
    const action = requiredString(body.action, "a operacao");

    if (action === "list") {
      const { data: authData, error: authError } = await admin.auth.admin.listUsers({ page: 1, perPage: 1000 });
      if (authError) throw authError;
      const { data: profiles, error: profilesError } = await admin.from("profiles").select("id,full_name,email,role,active");
      if (profilesError) throw profilesError;
      const profileMap = new Map((profiles || []).map((profile) => [profile.id, profile]));
      const users = (authData.users || []).map((user) => {
        const profile = profileMap.get(user.id) || {};
        return {
          id: user.id,
          email: user.email || profile.email || "",
          full_name: profile.full_name || user.user_metadata?.full_name || "",
          role: publicRole(profile.role || user.user_metadata?.role),
          active: profile.active !== false && !user.banned_until,
          created_at: user.created_at,
          last_sign_in_at: user.last_sign_in_at,
        };
      }).sort((a, b) => a.email.localeCompare(b.email));
      return json(req, { users });
    }

    if (action === "create") {
      const fullName = requiredString(body.full_name, "o nome completo");
      const email = requiredString(body.email, "o e-mail").toLowerCase();
      const password = requiredString(body.password, "a senha");
      const role = profileRole(body.role);
      if (password.length < 8) return json(req, { error: "A senha deve ter pelo menos 8 caracteres." }, 400);
      const { data, error } = await admin.auth.admin.createUser({
        email,
        password,
        email_confirm: true,
        user_metadata: { full_name: fullName, role },
      });
      if (error || !data.user) throw error || new Error("Usuario nao foi criado.");
      const { error: profileError } = await admin.from("profiles").upsert({
        id: data.user.id,
        full_name: fullName,
        email,
        role,
        active: true,
      }, { onConflict: "id" });
      if (profileError) {
        await admin.auth.admin.deleteUser(data.user.id);
        throw profileError;
      }
      return json(req, { ok: true, user_id: data.user.id });
    }

    const userId = requiredString(body.user_id, "o usuario");
    const { data: targetData, error: targetError } = await admin.auth.admin.getUserById(userId);
    if (targetError || !targetData.user) return json(req, { error: "Usuario nao encontrado." }, 404);
    const targetEmail = String(targetData.user.email || "").toLowerCase();

    if (action === "setPassword") {
      const password = requiredString(body.password, "a nova senha");
      if (password.length < 8) return json(req, { error: "A senha deve ter pelo menos 8 caracteres." }, 400);
      const { error } = await admin.auth.admin.updateUserById(userId, { password });
      if (error) throw error;
      return json(req, { ok: true });
    }

    if (action === "setRole") {
      if (targetEmail === ADMIN_EMAIL) return json(req, { error: "O perfil do administrador principal nao pode ser alterado." }, 400);
      const role = profileRole(body.role);
      const { error: profileError } = await admin.from("profiles").update({ role }).eq("id", userId);
      if (profileError) throw profileError;
      const metadata = { ...(targetData.user.user_metadata || {}), role };
      const { error: authError } = await admin.auth.admin.updateUserById(userId, { user_metadata: metadata });
      if (authError) throw authError;
      return json(req, { ok: true });
    }

    if (action === "setActive") {
      if (targetEmail === ADMIN_EMAIL) return json(req, { error: "O administrador principal nao pode ser desativado." }, 400);
      const active = body.active === true;
      const { error: authError } = await admin.auth.admin.updateUserById(userId, { ban_duration: active ? "none" : "876000h" });
      if (authError) throw authError;
      const { error: profileError } = await admin.from("profiles").update({ active }).eq("id", userId);
      if (profileError) throw profileError;
      return json(req, { ok: true });
    }

    if (action === "delete") {
      if (targetEmail === ADMIN_EMAIL) return json(req, { error: "O administrador principal nao pode ser excluido." }, 400);
      const { error } = await admin.auth.admin.deleteUser(userId);
      if (error) throw error;
      await admin.from("profiles").delete().eq("id", userId);
      return json(req, { ok: true });
    }

    return json(req, { error: "Operacao desconhecida." }, 400);
  } catch (error) {
    const message = error instanceof Error
      ? error.message
      : (error && typeof error === "object" && "message" in error)
        ? String(error.message)
        : "Erro interno.";
    return json(req, { error: message }, 500);
  }
});
