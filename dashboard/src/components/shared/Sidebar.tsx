import { useCallback, useEffect } from "react";
import { useLocation, useNavigate, useSearchParams } from "react-router-dom";
import {
  Sidebar,
  SidebarHeader,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarTrigger,
  SidebarRail,
} from "@cloudflare/kumo/components/sidebar";
import { Badge } from "@cloudflare/kumo/components/badge";
import {
  House,
  ChartBar,
  Cpu,
  Play,
  Plugs,
  GearSix,
  MagnifyingGlass,
  CaretUpDown,
  Pulse,
  ListChecks,
} from "@phosphor-icons/react";

export function AppSidebar() {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const runId = searchParams.get("run_id");

  const withRunId = useCallback(
    (path: string) =>
      runId
        ? `${path}${path.includes("?") ? "&" : "?"}run_id=${encodeURIComponent(runId)}`
        : path,
    [runId],
  );

  useEffect(() => {
    let lastKey = "";
    let lastKeyTime = 0;

    const handleKeyDown = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement;
      if (
        ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName) ||
        target.isContentEditable
      ) {
        return;
      }

      const now = Date.now();
      if (lastKey === "g" && now - lastKeyTime < 1000) {
        const map: Record<string, string> = {
          o: "/overview",
          m: "/meta-alerts",
          r: "/rbta",
          d: "/demo",
          l: "/live",
          s: "/system",
        };
        if (map[e.key]) {
          e.preventDefault();
          navigate(withRunId(map[e.key]));
        }
        lastKey = "";
        return;
      }

      if (e.key === "g") {
        lastKey = "g";
        lastKeyTime = now;
      } else {
        lastKey = "";
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [withRunId, navigate]);

  const openSearch = () => {
    window.dispatchEvent(
      new KeyboardEvent("keydown", { key: "/", bubbles: true }),
    );
  };

  const isPathActive = (path: string) => {
    if (path === "/overview")
      return location.pathname === "/overview" || location.pathname === "/";
    return (
      location.pathname === path || location.pathname.startsWith(path + "/")
    );
  };

  return (
    <Sidebar>
      <SidebarHeader className="p-3 border-b border-kumo-line flex items-center justify-between">
        <div className="flex items-center gap-2.5 min-w-0 ml-4">
          <span className="font-semibold text-base text-kumo-strong truncate group-data-[state=collapsed]/sidebar:hidden">
            RBTA Platform
          </span>
        </div>
        <CaretUpDown
          size={16}
          className="text-kumo-subtle shrink-0 group-data-[state=collapsed]/sidebar:hidden"
        />
      </SidebarHeader>

      <SidebarContent>
        <div className="px-2 pt-2 pb-1 group-data-[state=collapsed]/sidebar:px-1">
          <button
            type="button"
            onClick={openSearch}
            className="w-full flex items-center justify-between gap-2 px-3 py-2 rounded-lg border border-kumo-line bg-kumo-recessed/40 text-kumo-subtle hover:text-kumo-default hover:bg-kumo-recessed text-sm transition-colors cursor-pointer group-data-[state=collapsed]/sidebar:justify-center group-data-[state=collapsed]/sidebar:px-0"
            title="Cari (tekan / atau ⌘K)"
          >
            <div className="flex items-center gap-2.5 truncate">
              <MagnifyingGlass size={16} className="shrink-0" />
              <span className="truncate group-data-[state=collapsed]/sidebar:hidden">
                Cari…
              </span>
            </div>
            <kbd className="hidden sm:inline-flex rounded border border-kumo-line bg-kumo-canvas px-1.5 py-0.5 text-xs font-mono text-kumo-subtle group-data-[state=collapsed]/sidebar:hidden">
              ⌘K
            </kbd>
          </button>
        </div>

        <SidebarGroup>
          <SidebarMenu>
            <SidebarMenuItem>
              <SidebarMenuButton
                icon={House}
                active={isPathActive("/overview")}
                tooltip="Ringkasan: kondisi alert dan beban analyst"
                onClick={() => navigate(withRunId("/overview"))}
              >
                Ringkasan
              </SidebarMenuButton>
            </SidebarMenuItem>

            <SidebarMenuItem>
              <SidebarMenuButton
                icon={ChartBar}
                active={isPathActive("/meta-alerts")}
                tooltip="Daftar meta-alert: telusuri kelompok alert dan skornya"
                onClick={() => navigate(withRunId("/meta-alerts"))}
              >
                Daftar meta-alert
              </SidebarMenuButton>
            </SidebarMenuItem>

            <SidebarMenuItem>
              <SidebarMenuButton
                icon={Cpu}
                active={isPathActive("/rbta")}
                tooltip="Status pengelompokan: kelompok terbuka dan jendela waktu per agen"
                onClick={() => navigate(withRunId("/rbta"))}
              >
                Status pengelompokan
              </SidebarMenuButton>
            </SidebarMenuItem>
          </SidebarMenu>
        </SidebarGroup>

        <SidebarGroup>
          <SidebarMenu>
            <SidebarMenuItem>
              <SidebarMenuButton
                icon={Pulse}
                active={isPathActive("/live")}
                tooltip="Pemantauan live: status pemrosesan dan kesegaran data"
                onClick={() => navigate(withRunId("/live"))}
              >
                Pemantauan live
              </SidebarMenuButton>
            </SidebarMenuItem>
            <SidebarMenuItem>
              <SidebarMenuButton
                icon={ListChecks}
                active={isPathActive("/review-queue")}
                tooltip="Antrean review: label hasil pengecekan analyst"
                onClick={() => navigate("/review-queue")}
              >
                Antrean review
              </SidebarMenuButton>
            </SidebarMenuItem>
            <SidebarMenuItem>
              <SidebarMenuButton
                icon={Play}
                active={isPathActive("/demo")}
                tooltip="Replay sidang: putar ulang data penelitian dan hasil evaluasi"
                onClick={() => navigate(withRunId("/demo"))}
              >
                Replay sidang
              </SidebarMenuButton>
            </SidebarMenuItem>
          </SidebarMenu>
        </SidebarGroup>

        <SidebarGroup>
          <SidebarMenu>
            <SidebarMenuItem>
              <SidebarMenuButton
                icon={Plugs}
                active={isPathActive("/integrations")}
                tooltip="Integrasi: status Telegram dan Shuffle"
                onClick={() => navigate(withRunId("/integrations"))}
              >
                Integrasi
              </SidebarMenuButton>
            </SidebarMenuItem>

            <SidebarMenuItem>
              <SidebarMenuButton
                icon={GearSix}
                active={isPathActive("/system")}
                tooltip="Sistem: versi model dan konfigurasi"
                onClick={() => navigate(withRunId("/system"))}
              >
                Sistem
              </SidebarMenuButton>
            </SidebarMenuItem>
          </SidebarMenu>
        </SidebarGroup>
      </SidebarContent>

      <SidebarFooter className="p-3 border-t border-kumo-line flex items-center justify-between">
        <SidebarTrigger />
        <div className="flex items-center gap-1.5 group-data-[state=collapsed]/sidebar:hidden">
          <Badge variant="secondary">v1.0.0</Badge>
        </div>
      </SidebarFooter>

      <SidebarRail />
    </Sidebar>
  );
}
