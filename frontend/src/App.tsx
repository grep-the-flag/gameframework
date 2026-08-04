import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";

export default function App() {
  const { t } = useTranslation();
  return (
    <main className="flex min-h-screen flex-col items-center justify-center gap-4">
      <h1 className="text-3xl font-bold">{t("app.title")}</h1>
      <p className="text-muted-foreground">{t("app.tagline")}</p>
      <Button>{t("app.title")}</Button>
    </main>
  );
}
