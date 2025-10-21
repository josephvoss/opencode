import { Auth } from "../../auth"
import { cmd } from "./cmd"
import * as prompts from "@clack/prompts"
import { UI } from "../ui"
import { ModelsDev } from "../../provider/models"
import { map, pipe, sortBy, values } from "remeda"
import path from "path"
import os from "os"
import { Global } from "../../global"
import { Plugin } from "../../plugin"
import { Instance } from "../../project/instance"
import { Client } from "@modelcontextprotocol/sdk/client/index.js"
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js"
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js"
import type { OAuthClientProvider } from "@modelcontextprotocol/sdk/client/auth.js"
import { Config } from "../../config/config"
import { Log } from "../../util/log"

const log = Log.create({ service: "auth" })

class SecureOAuthProvider implements OAuthClientProvider {
  private serverKey: string
  private redirectUri: string
  private clientName: string
  private service: string
  private _state: string
  private storagePath: string
  private resourceParams?: string

  constructor(serverKey: string, redirectUri: string, clientName: string = "opencode", resourceParams?: string) {
    this.serverKey = serverKey
    this.redirectUri = redirectUri
    this.clientName = clientName
    this.service = `ai.opencode.mcp.${serverKey}`
    this._state = serverKey
    this.storagePath = path.join(Global.Path.data, "mcp-auth", serverKey)
    if (resourceParams) {
      this.resourceParams = resourceParams
    }
  }

  private getSecretPath(name: string): string {
    return path.join(this.storagePath, name)
  }

  private async ensureStorageDir(): Promise<void> {
    try {
      await Bun.file(this.storagePath).exists()
    } catch {
      await Bun.$`mkdir -p ${this.storagePath}`
    }
  }

  get redirectUrl(): string | URL {
    return this.redirectUri
  }

  get clientMetadata() {
    return {
      redirect_uris: [this.redirectUri],
      token_endpoint_auth_method: "none" as const,
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      client_name: this.clientName,
    }
  }

  state(): string {
    return this._state
  }

  async clientInformation() {
    try {
      const data = await Bun.file(this.getSecretPath("client.json")).text()
      return JSON.parse(data)
    } catch {
      return undefined
    }
  }

  async saveClientInformation(clientInformation: any): Promise<void> {
    await this.ensureStorageDir()
    await Bun.write(this.getSecretPath("client.json"), JSON.stringify(clientInformation))
  }

  async tokens() {
    try {
      const data = await Bun.file(this.getSecretPath("tokens.json")).text()
      return JSON.parse(data)
    } catch {
      return undefined
    }
  }

  async saveTokens(tokens: any): Promise<void> {
    await this.ensureStorageDir()
    await Bun.write(this.getSecretPath("tokens.json"), JSON.stringify(tokens))
  }

  async redirectToAuthorization(authUrl: URL): Promise<void> {
    if (this.resourceParams) {
      authUrl.searchParams.set("resource", this.resourceParams)
    }
    log.warn("OAuth authorization required", {
      message: "Please visit the following URL to authorize",
      url: authUrl.toString(),
    })
    try {
      // gross
      const command = process.platform === "darwin" ? "open" : process.platform === "win32" ? "start" : "xdg-open"
      Bun.spawn([command, authUrl.toString()], { stdout: "ignore", stderr: "ignore" })
    } catch (error) {
      log.warn("Failed to open browser automatically", { error })
    }
  }

  async saveCodeVerifier(codeVerifier: string): Promise<void> {
    await this.ensureStorageDir()
    await Bun.write(this.getSecretPath("verifier.txt"), codeVerifier)
  }

  async codeVerifier(): Promise<string> {
    try {
      const verifier = await Bun.file(this.getSecretPath("verifier.txt")).text()
      if (!verifier) throw new Error("No code verifier saved for session")
      return verifier
    } catch {
      throw new Error("No code verifier saved for session")
    }
  }

  async invalidateCredentials(scope: "all" | "client" | "tokens" | "verifier"): Promise<void> {
    const files = {
      all: ["client.json", "tokens.json", "verifier.txt"],
      client: ["client.json"],
      tokens: ["tokens.json"],
      verifier: ["verifier.txt"],
    }

    for (const file of files[scope]) {
      try {
        await Bun.$`rm -f ${this.getSecretPath(file)}`
      } catch {}
    }
  }
}

export const AuthCommand = cmd({
  command: "auth",
  describe: "manage credentials",
  builder: (yargs) =>
    yargs
      .command(AuthLoginCommand)
      .command(AuthLogoutCommand)
      .command(AuthListCommand)
      .command(AuthMcpCommand)
      .demandCommand(),
  async handler() {},
})

export const AuthListCommand = cmd({
  command: "list",
  aliases: ["ls"],
  describe: "list providers",
  async handler() {
    UI.empty()
    const authPath = path.join(Global.Path.data, "auth.json")
    const homedir = os.homedir()
    const displayPath = authPath.startsWith(homedir) ? authPath.replace(homedir, "~") : authPath
    prompts.intro(`Credentials ${UI.Style.TEXT_DIM}${displayPath}`)
    const results = await Auth.all().then((x) => Object.entries(x))
    const database = await ModelsDev.get()

    for (const [providerID, result] of results) {
      const name = database[providerID]?.name || providerID
      prompts.log.info(`${name} ${UI.Style.TEXT_DIM}${result.type}`)
    }

    prompts.outro(`${results.length} credentials`)

    // Environment variables section
    const activeEnvVars: Array<{ provider: string; envVar: string }> = []

    for (const [providerID, provider] of Object.entries(database)) {
      for (const envVar of provider.env) {
        if (process.env[envVar]) {
          activeEnvVars.push({
            provider: provider.name || providerID,
            envVar,
          })
        }
      }
    }

    if (activeEnvVars.length > 0) {
      UI.empty()
      prompts.intro("Environment")

      for (const { provider, envVar } of activeEnvVars) {
        prompts.log.info(`${provider} ${UI.Style.TEXT_DIM}${envVar}`)
      }

      prompts.outro(`${activeEnvVars.length} environment variable` + (activeEnvVars.length === 1 ? "" : "s"))
    }
  },
})

export const AuthMcpCommand = cmd({
  command: "mcp",
  describe: "manage MCP server credentials",
  builder: (yargs) => yargs.command(AuthMcpLoginCommand).demandCommand(),
  async handler() {},
})

export const AuthMcpLoginCommand = cmd({
  command: "login [server]",
  describe: "log in to an MCP server",
  builder: (yargs) =>
    yargs.positional("server", {
      describe: "MCP server name from config",
      type: "string",
    }),
  async handler(args) {
    await Instance.provide({
      directory: process.cwd(),
      async fn() {
        UI.empty()
        prompts.intro("MCP server login")

        const cfg = await Config.get()
        const mcpServers = cfg.mcp ?? {}
        const remoteServers = Object.entries(mcpServers).filter(([_, config]) => config.type === "remote")

        if (remoteServers.length === 0) {
          prompts.log.error("No remote MCP servers configured in opencode.json")
          prompts.outro("Done")
          return
        }

        let serverKey = args.server
        if (!serverKey) {
          const selected = await prompts.select({
            message: "Select MCP server",
            options: remoteServers.map(([key, config]) => ({
              label: key,
              value: key,
              hint: config.type === "remote" ? config.url : undefined,
            })),
          })
          if (prompts.isCancel(selected)) throw new UI.CancelledError()
          serverKey = selected as string
        }

        const mcpConfig = mcpServers[serverKey]
        if (!mcpConfig) {
          prompts.log.error(`MCP server "${serverKey}" not found in config`)
          prompts.outro("Done")
          return
        }

        if (mcpConfig.type !== "remote") {
          prompts.log.error("Only remote MCP servers support authentication")
          prompts.outro("Done")
          return
        }

        prompts.log.info(`Authenticating with ${serverKey}`)
        prompts.log.info(`Server: ${mcpConfig.url}`)

        const callbackPort = 0
        let authCode: string | undefined
        let authResolve: ((value: string) => void) | undefined

        const waitForAuthCode = new Promise<string>((resolve) => {
          authResolve = resolve
        })

        const server = Bun.serve({
          port: callbackPort,
          fetch(req) {
            const url = new URL(req.url)
            if (url.pathname === "/oauth/callback") {
              const code = url.searchParams.get("code")
              if (code) {
                authCode = code
                authResolve?.(code)
                return new Response(
                  "<html><body><h1>Authentication successful!</h1><p>You can close this window and return to the CLI.</p></body></html>",
                  {
                    headers: { "Content-Type": "text/html" },
                  },
                )
              }
              return new Response("<html><body><h1>Authentication failed</h1><p>No code received</p></body></html>", {
                status: 400,
                headers: { "Content-Type": "text/html" },
              })
            }
            return new Response("Not found", { status: 404 })
          },
        })

        const actualPort = server.port
        const redirectUri = `http://localhost:${actualPort}/oauth/callback`
        const mcpUrl = new URL(mcpConfig.url)
        const provider = new SecureOAuthProvider(serverKey, redirectUri, "opencode", mcpUrl.origin)

        const spinner = prompts.spinner()
        spinner.start("Connecting to MCP server...")

        try {
          const client = new Client(
            {
              name: "opencode-auth",
              version: "1.0.0",
            },
            {
              capabilities: {},
            },
          )

          const transports = [
            {
              name: "StreamableHTTP",
              create: () => new StreamableHTTPClientTransport(new URL(mcpConfig.url), { authProvider: provider }),
            },
            {
              name: "SSE",
              create: () => new SSEClientTransport(new URL(mcpConfig.url), { authProvider: provider }),
            },
          ]

          let lastError: Error | undefined
          let success = false

          for (const { name, create } of transports) {
            const transport = create()
            try {
              await client.connect(transport)
              spinner.stop("Already authenticated")
              prompts.log.success(`Already authenticated with ${serverKey} (${name})`)
              success = true
              break
            } catch (error: any) {
              if (error?.message?.includes("Unauthorized") || error?.code === "UNAUTHORIZED") {
                spinner.message("Authorization required, opening browser...")

                const code = await waitForAuthCode

                spinner.message("Completing authorization...")
                try {
                  await transport.finishAuth(code)
                  spinner.stop("Login successful")
                  prompts.log.success(`Successfully authenticated with ${serverKey} (${name})`)
                  prompts.log.info(
                    "Tokens have been saved and will be used automatically when connecting to this MCP server",
                  )
                  success = true
                  break
                } catch (finishError: any) {
                  lastError = finishError instanceof Error ? finishError : new Error(String(finishError))
                  log.error("finishAuth failed", { transport: name, error: finishError, code })
                }
              } else {
                lastError = error instanceof Error ? error : new Error(String(error))
                log.error("transport connection failed", { transport: name, error: lastError.message })
              }
            } finally {
              try {
                await client.close()
              } catch {}
            }
          }

          if (!success) {
            spinner.stop("Failed to authorize", 1)
            log.error("OAuth flow failed", { error: lastError })
            prompts.log.error(`Error: ${lastError?.message || "All transports failed"}`)
          }
        } catch (error) {
          spinner.stop("Failed to authorize", 1)
          log.error("OAuth flow failed", { error })
          prompts.log.error(`Error: ${error instanceof Error ? error.message : String(error)}`)
        } finally {
          server.stop()
        }

        prompts.outro("Done")
      },
    })
  },
})

export const AuthLoginCommand = cmd({
  command: "login [url]",
  describe: "log in to a provider",
  builder: (yargs) =>
    yargs.positional("url", {
      describe: "opencode auth provider",
      type: "string",
    }),
  async handler(args) {
    await Instance.provide({
      directory: process.cwd(),
      async fn() {
        UI.empty()
        prompts.intro("Add credential")
        if (args.url) {
          const wellknown = await fetch(`${args.url}/.well-known/opencode`).then((x) => x.json() as any)
          prompts.log.info(`Running \`${wellknown.auth.command.join(" ")}\``)
          const proc = Bun.spawn({
            cmd: wellknown.auth.command,
            stdout: "pipe",
          })
          const exit = await proc.exited
          if (exit !== 0) {
            prompts.log.error("Failed")
            prompts.outro("Done")
            return
          }
          const token = await new Response(proc.stdout).text()
          await Auth.set(args.url, {
            type: "wellknown",
            key: wellknown.auth.env,
            token: token.trim(),
          })
          prompts.log.success("Logged into " + args.url)
          prompts.outro("Done")
          return
        }
        await ModelsDev.refresh().catch(() => {})
        const providers = await ModelsDev.get()
        const priority: Record<string, number> = {
          opencode: 0,
          anthropic: 1,
          "github-copilot": 2,
          openai: 3,
          google: 4,
          openrouter: 5,
          vercel: 6,
        }
        let provider = await prompts.autocomplete({
          message: "Select provider",
          maxItems: 8,
          options: [
            ...pipe(
              providers,
              values(),
              sortBy(
                (x) => priority[x.id] ?? 99,
                (x) => x.name ?? x.id,
              ),
              map((x) => ({
                label: x.name,
                value: x.id,
                hint: priority[x.id] <= 1 ? "recommended" : undefined,
              })),
            ),
            {
              value: "other",
              label: "Other",
            },
          ],
        })

        if (prompts.isCancel(provider)) throw new UI.CancelledError()

        const plugin = await Plugin.list().then((x) => x.find((x) => x.auth?.provider === provider))
        if (plugin && plugin.auth) {
          let index = 0
          if (plugin.auth.methods.length > 1) {
            const method = await prompts.select({
              message: "Login method",
              options: [
                ...plugin.auth.methods.map((x, index) => ({
                  label: x.label,
                  value: index.toString(),
                })),
              ],
            })
            if (prompts.isCancel(method)) throw new UI.CancelledError()
            index = parseInt(method)
          }
          const method = plugin.auth.methods[index]

          // Handle prompts for all auth types
          await new Promise((resolve) => setTimeout(resolve, 10))
          const inputs: Record<string, string> = {}
          if (method.prompts) {
            for (const prompt of method.prompts) {
              if (prompt.condition && !prompt.condition(inputs)) {
                continue
              }
              if (prompt.type === "select") {
                const value = await prompts.select({
                  message: prompt.message,
                  options: prompt.options,
                })
                if (prompts.isCancel(value)) throw new UI.CancelledError()
                inputs[prompt.key] = value
              } else {
                const value = await prompts.text({
                  message: prompt.message,
                  placeholder: prompt.placeholder,
                  validate: prompt.validate ? (v) => prompt.validate!(v ?? "") : undefined,
                })
                if (prompts.isCancel(value)) throw new UI.CancelledError()
                inputs[prompt.key] = value
              }
            }
          }

          if (method.type === "oauth") {
            const authorize = await method.authorize(inputs)

            if (authorize.url) {
              prompts.log.info("Go to: " + authorize.url)
            }

            if (authorize.method === "auto") {
              if (authorize.instructions) {
                prompts.log.info(authorize.instructions)
              }
              const spinner = prompts.spinner()
              spinner.start("Waiting for authorization...")
              const result = await authorize.callback()
              if (result.type === "failed") {
                spinner.stop("Failed to authorize", 1)
              }
              if (result.type === "success") {
                const saveProvider = result.provider ?? provider
                if ("refresh" in result) {
                  const { type: _, provider: __, refresh, access, expires, ...extraFields } = result
                  await Auth.set(saveProvider, {
                    type: "oauth",
                    refresh,
                    access,
                    expires,
                    ...extraFields,
                  })
                }
                if ("key" in result) {
                  await Auth.set(saveProvider, {
                    type: "api",
                    key: result.key,
                  })
                }
                spinner.stop("Login successful")
              }
            }

            if (authorize.method === "code") {
              const code = await prompts.text({
                message: "Paste the authorization code here: ",
                validate: (x) => (x && x.length > 0 ? undefined : "Required"),
              })
              if (prompts.isCancel(code)) throw new UI.CancelledError()
              const result = await authorize.callback(code)
              if (result.type === "failed") {
                prompts.log.error("Failed to authorize")
              }
              if (result.type === "success") {
                const saveProvider = result.provider ?? provider
                if ("refresh" in result) {
                  const { type: _, provider: __, refresh, access, expires, ...extraFields } = result
                  await Auth.set(saveProvider, {
                    type: "oauth",
                    refresh,
                    access,
                    expires,
                    ...extraFields,
                  })
                }
                if ("key" in result) {
                  await Auth.set(saveProvider, {
                    type: "api",
                    key: result.key,
                  })
                }
                prompts.log.success("Login successful")
              }
            }

            prompts.outro("Done")
            return
          }

          if (method.type === "api") {
            if (method.authorize) {
              const result = await method.authorize(inputs)
              if (result.type === "failed") {
                prompts.log.error("Failed to authorize")
              }
              if (result.type === "success") {
                const saveProvider = result.provider ?? provider
                await Auth.set(saveProvider, {
                  type: "api",
                  key: result.key,
                })
                prompts.log.success("Login successful")
              }
              prompts.outro("Done")
              return
            }
          }
        }

        if (provider === "other") {
          provider = await prompts.text({
            message: "Enter provider id",
            validate: (x) => (x && x.match(/^[0-9a-z-]+$/) ? undefined : "a-z, 0-9 and hyphens only"),
          })
          if (prompts.isCancel(provider)) throw new UI.CancelledError()
          provider = provider.replace(/^@ai-sdk\//, "")
          if (prompts.isCancel(provider)) throw new UI.CancelledError()
          prompts.log.warn(
            `This only stores a credential for ${provider} - you will need configure it in opencode.json, check the docs for examples.`,
          )
        }

        if (provider === "amazon-bedrock") {
          prompts.log.info(
            "Amazon bedrock can be configured with standard AWS environment variables like AWS_BEARER_TOKEN_BEDROCK, AWS_PROFILE or AWS_ACCESS_KEY_ID",
          )
          prompts.outro("Done")
          return
        }

        if (provider === "opencode") {
          prompts.log.info("Create an api key at https://opencode.ai/auth")
        }

        if (provider === "vercel") {
          prompts.log.info("You can create an api key at https://vercel.link/ai-gateway-token")
        }

        const key = await prompts.password({
          message: "Enter your API key",
          validate: (x) => (x && x.length > 0 ? undefined : "Required"),
        })
        if (prompts.isCancel(key)) throw new UI.CancelledError()
        await Auth.set(provider, {
          type: "api",
          key,
        })

        prompts.outro("Done")
      },
    })
  },
})

export const AuthLogoutCommand = cmd({
  command: "logout",
  describe: "log out from a configured provider",
  async handler() {
    UI.empty()
    const credentials = await Auth.all().then((x) => Object.entries(x))
    prompts.intro("Remove credential")
    if (credentials.length === 0) {
      prompts.log.error("No credentials found")
      return
    }
    const database = await ModelsDev.get()
    const providerID = await prompts.select({
      message: "Select provider",
      options: credentials.map(([key, value]) => ({
        label: (database[key]?.name || key) + UI.Style.TEXT_DIM + " (" + value.type + ")",
        value: key,
      })),
    })
    if (prompts.isCancel(providerID)) throw new UI.CancelledError()
    await Auth.remove(providerID)
    prompts.outro("Logout successful")
  },
})
