window.__ModuleLoader__.load({
	id: "dsh-login-gateway",
	factory: (require) => {
		var module = { exports: {} };
		var exports = module.exports;
		Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });

		/**
		 * Client projection of dsh-login-gateway.
		 *
		 * 经门卫反代（外部域名/IP）访问 dsh 时，服务端会把 Host/Origin 改回
		 * 127.0.0.1 以通过信任围栏，但浏览器端 `location.hostname` 仍是外部域名，
		 * 导致 `dsh-client-connection` 把 `isLoopback` 判为 false，进而让
		 * `dsh-client-ui-settings` 走 memory 持久化（设置/模型/插件配置全部失效，
		 * 且无报错）。这里在浏览器端把 `isLoopback` 修正为 true，使三问题恢复。
		 */

		/** Required Client services: the dsh Connection carrier provided by dsh-client-connection. */
		const inject = ["connection"];

		/**
		 * Browser-side entry. 同步执行（Cordis 要求 apply 不 async）。
		 * 全程 try/catch，绝不让本插件内部异常影响 dsh boot。
		 */
		function apply(ctx) {
			try {
				// 1) 先置 isLoopback —— 若 ui-settings 尚未 activate，其构造时读到 true 自会走 host。
				const conn = typeof ctx.get === "function" ? ctx.get("connection", false) : ctx.connection;
				if (conn && !conn.isLoopback) {
					conn.isLoopback = true;
				}

				// 2) 若 ui-settings 已先 activate（immediately 核心件，几乎必然如此），
				//    其 mirror 已在构造时用 memory 定死 persistence —— 必须就地修复已建 mirror。
				//    SettingsScopeBinder（服务名 settingsScope）上挂着共享的 SettingsDescribeMirror。
				let scope;
				try {
					scope = typeof ctx.get === "function" ? ctx.get("settingsScope", false) : ctx.settingsScope;
				} catch (error) {
					scope = void 0;
				}
				const mirror = scope && scope.mirror;
				if (mirror && mirror.persistence === "memory") {
					// 改 persistence 为 host，让后续 load() 真正从 Host 拉 settings.describe。
					mirror.persistence = "host";
					// 修快照：persistence 已 host，unavailable 状态不符 → 置回 idle 等待 load 落地。
					const current = (typeof mirror.getSnapshot === "function" && mirror.store && typeof mirror.store.set === "function")
						? mirror.getSnapshot()
						: void 0;
					if (current) {
						mirror.store.set({
							status: "idle",
							view: current.view,
							error: null
						});
					}
					// 从 Host 拉 describe 并刷新 store；UI scope 订阅共享 mirror，自动刷新。
					if (typeof mirror.load === "function") {
						mirror.load();
					}
				}

				// 3) 包装 settingsScope.bind：任何 namespace 惰性 bind（设置页/模型选择器/
				//    插件配置等所有 scope）都在 controller 创建（读 connection.isLoopback）
				//    之前强制 isLoopback=true，保证每个 controller 都以 host 创建 →
				//    写路径 enqueue() 走 RPC 持久化，刷新保留。
				//    由于 bind 内部用 ctx.get("connection") 读的是共享 handle，这里改同一
				//    handle 的 isLoopback 即可覆盖任何 bind 时序。
				if (scope && typeof scope.bind === "function" && !scope.bind.__gwHost__) {
					const origBind = scope.bind;
					scope.bind = function (spec) {
						try {
							const c = typeof ctx.get === "function" ? ctx.get("connection", false) : ctx.connection;
							if (c && !c.isLoopback) {
								c.isLoopback = true;
							}
						} catch (error) {
							// 静默：即使失败，原 bind 照常执行
						}
						return origBind.call(this, spec);
					};
					scope.bind.__gwHost__ = true;
				}
			} catch (error) {
				// 静默失败：不阻断 dsh boot
			}
		}

		exports.apply = apply;
		exports.inject = inject;

		return module.exports;
	}
});
