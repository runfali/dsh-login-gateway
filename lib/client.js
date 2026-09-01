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

				// 2) 兜底修复：万一 ui-settings 抢在本插件之前 activate，它已经把
				//    persistence 定死成 memory 并分别存进了两个对象——
				//    SettingsScopeBinder（服务名 settingsScope）自己一份，
				//    以及它持有的共享 SettingsDescribeMirror 一份。0.1.2-alpha.1 起
				//    binder 不再按 bind() 时序回读 connection，两处必须一起翻，
				//    只翻 mirror 会让新 bind 出来的 scope 仍是 memory。
				let scope;
				try {
					scope = typeof ctx.get === "function" ? ctx.get("settingsScope", false) : ctx.settingsScope;
				} catch (error) {
					scope = void 0;
				}
				const mirror = scope && scope.mirror;
				if (scope && scope.persistence === "memory") {
					scope.persistence = "host";
				}
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
				// ponytail: 此兜底修不了「翻之前已经 bind() 出去的 scope」——
				// 它们各自持有一份 persistence 副本。正常时序（本插件 immediately，
				// ui-settings 非 immediately）走不到这里；真出现时升级 dsh 或调整
				// profile 里 bundle 顺序即可，不值得在此反射遍历 Cordis fiber。
			} catch (error) {
				// 静默失败：不阻断 dsh boot
			}
		}

		exports.apply = apply;
		exports.inject = inject;

		return module.exports;
	}
});
