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
		 * 导致 dsh 把会话判为非 loopback，进而让 `dsh-client-ui-settings` 走 memory
		 * 持久化（设置/模型/插件配置全部失效，且无报错）。这里在浏览器端把
		 * loopback 判定修正为 true，使这些能力恢复。
		 *
		 * 0.1.7-rc.1 契约复核（逐包源码比对，本仓库 0.1.7 适配轮）：
		 * - `dsh-client-connection` 客户端仍以可写的 `handle.isLoopback` 暴露判定；
		 *   connection handle / `$host` / `hostFacts`（缓存键只有 `home`）形状与
		 *   0.1.5 逐字一致，且 settings 持久化与 settings-general 的「打开配置文件」
		 *   入口仍在 activation 期读 `ctx.remote.$host.isLoopback`。
		 * - 0.1.5 的 settingsScope 服务已移除，宿主改为 configForms 服务
		 *   （dsh-client-ui-settings），同样持有 persistence + mirror 两个同名字段，
		 *   mirror 仍是 SettingsDescribeMirror（store 快照 {status, view, error}，
		 *   getSnapshot/load 同名）。兜底修复同时尝试两个服务名，跨版本兼容。
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

				// 1b) `remote.$host` 的 hostFacts 缓存修正（0.1.2+ / 0.1.5 均适用）。
				//     `$host` getter：home 未变就复用旧 hostFacts；旧值可能是在我们修正
				//     conn.isLoopback 之前取的（isLoopback:false）。就地改缓存值即可：
				//     下一次 getter 调用 home 未变 → 直接返回我们改过的对象。
				const remote = ctx.get && ctx.get("remote", false);
				const facts = remote && remote.hostFacts;
				if (facts && facts.isLoopback === false) {
					facts.isLoopback = true;
				}

				// 2) 兜底修复：万一 ui-settings 抢在本插件之前 activate，它已经把
				//    persistence 定死成 memory，并分别存进了「宿主服务对象」与它持有的
				//    共享 SettingsDescribeMirror 两处。两处必须一起翻，只翻 mirror
				//    会让后续新建的表单仍拿 memory。
				//    0.1.5-rc.1 及更早：宿主服务名是 settingsScope。
				//    0.1.7-rc.1 起：settingsScope 已移除，改为 configForms（同样持有
				//    mirror + persistence 两个同名字段，mirror 形状不变：store 快照
				//    {status, view, error}、getSnapshot/load 同名）。两个服务名都试，
				//    命中哪个修哪个，跨版本兼容。
				const repairPersistence = (owner) => {
					if (!owner || owner.persistence !== "memory") return;
					owner.persistence = "host";
					const mirror = owner.mirror;
					if (!mirror || mirror.persistence !== "memory") return;
					// 改 persistence 为 host，让后续 load() 真正从 Host 拉 settings.describe。
					mirror.persistence = "host";
					// 修快照：persistence 已 host，unavailable 状态不符 → 置回 idle 等待 load 落地。
					const current = (typeof mirror.getSnapshot === "function" && mirror.store && typeof mirror.store.set === "function")
						? mirror.getSnapshot()
						: void 0;
					if (current && current.status === "unavailable") {
						mirror.store.set({
							status: "idle",
							view: current.view,
							error: null
						});
					}
					// 从 Host 拉 describe 并刷新 store；订阅共享 mirror 的 UI 自动刷新。
					if (typeof mirror.load === "function") {
						mirror.load();
					}
				};
				for (const serviceName of ["settingsScope", "configForms"]) {
					let owner;
					try {
						owner = typeof ctx.get === "function" ? ctx.get(serviceName, false) : ctx[serviceName];
					} catch (error) {
						owner = void 0;
					}
					// 服务在但还没构造完（字段缺失）时同样按"无需修复"跳过
					if (owner && (owner.persistence !== undefined || owner.mirror)) {
						repairPersistence(owner);
					}
				}
				// ponytail: 此兜底修不了「翻之前已经用旧 persistence 构造出去的表单」——
				// 它们各自持有一份 persistence 副本。正常时序（本插件 immediately，
				// ui-settings 非 immediately）走不到这里；真出现时刷新页面或调整
				// profile 里 bundle 顺序即可，不值得在此反射遍历 Cordis fiber。

				// 3) 0.1.5 起 settings-general 的「打开配置文件」入口同样以
				//    `remote.$host.isLoopback` 门控：非 loopback 时该入口整块不渲染，
				//    即便服务端反代了 xdg-open 也点不到。上面 1/1b 已按同一时序修正，
				//    此处不再重复动作；保留注释以免后人误以为漏做。
			} catch (error) {
				// 静默失败：不阻断 dsh boot
			}
		}

		exports.apply = apply;
		exports.inject = inject;

		return module.exports;
	}
});
