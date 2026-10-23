Виконав: Гріненко Роман ІМ-44

## Опис проєкту

Сервіс аналітики безпекових подій, який обробляє нескінченні потоки логів (`Stream<SecurityLog>`)
за допомогою ледачих операцій Stream API, `Optional` та кастомного `Gatherer`. Збірка виконується
за допомогою Gradle, залежності (JUnit 5) керуються через Version Catalog (`gradle/libs.versions.toml`).

Усі класи знаходяться в пакеті `ua.kpi.comsys.streams`.

| Клас / метод | Результат | Механізм |
|---|---|---|
| `SecurityLog` | record події: IP, рівень, опис, час | — |
| `Optional<SecurityLog> findFirstCriticalEvent(Stream<SecurityLog> stream)` | перша подія з рівнем `CRITICAL` | `filter` + `findFirst` |
| `List<SecurityLog> getLogsBeforeDeadline(Stream<SecurityLog> stream, LocalDateTime deadline)` | події до настання дедлайну | `takeWhile` |
| `List<SecurityLog> getLogsInWindow(Stream<SecurityLog> stream, LocalDateTime from, LocalDateTime to)` | події в інтервалі `[from, to)` (додатковий метод) | `dropWhile` + `takeWhile` |
| `List<String> detectIpBursts(Stream<SecurityLog> stream, int burstThreshold, int maxIpsToReport)` | IP, що надіслали `>= burstThreshold` подій поспіль | `IpBurstGatherer` + `limit` |
| `IpBurstGatherer` | послідовний stateful `Gatherer<SecurityLog, State, String>` | `Gatherer.Integrator` |

Правила обробки:

- `CRITICAL` порівнюється точно (з урахуванням регістру та пробілів);
- `null`-елементи потоку пропускаються;
- до результату `getLogsBeforeDeadline` входять події з `timestamp` строго до дедлайну; збір зупиняється
  на першій події з часом `>= deadline` або без `timestamp` (вважається, що час у потоці не спадає);
- `IpBurstGatherer` рахує неперервну серію подій від однієї IP; подія від іншої IP, `null`-подія чи
  подія без IP скидає серію. IP додається до звіту в момент, коли серія досягає `burstThreshold`,
  кожна IP звітується лише один раз, порядок — за першим виявленням;
- обробка `detectIpBursts` зупиняється, щойно знайдено `maxIpsToReport` IP: `limit` відхиляє наступні
  елементи, і `Gatherer` перестає читати джерело.

Методи кидають `IllegalArgumentException`, якщо `stream`, `deadline`, `from` чи `to` дорівнюють `null`,
`from` пізніше за `to`, а також якщо `burstThreshold < 1` або `maxIpsToReport < 1`.

Обмеження: якщо в нескінченному потоці ніколи не з'явиться `CRITICAL`-подія, дедлайн
або потрібна кількість атак, відповідний виклик не завершиться — це властивість нескінченних джерел.

Використовується лише стандартна бібліотека Java; `Gatherer` є фінальним API з Java 24, тому проєкт
збирається на Java 25.

## Розрахунок варіанта

```
N = 5
V = N mod 3 = 5 mod 3 = 2
```

Варіант **V = 2** — обробка безпекових подій (`SecurityLogAnalyzer`).

## Запуск тестів

Потрібен JDK 17+ для запуску Gradle. Gradle встановлювати не потрібно, використовується Gradle Wrapper.
Для компіляції використовується toolchain JDK 25: якщо його немає локально, Gradle завантажить його
автоматично.

```
./gradlew test
```

Для Windows:

```
gradlew.bat test
```

Повна збірка разом з тестами:

```
./gradlew build
```

Тести (JUnit 5) використовують нескінченні джерела `Stream.iterate` та `Stream.generate` і мають
`@Timeout(2)`, що підтверджує відсутність зависань. Покрито: валідацію всіх аргументів, пошук
`CRITICAL`-події, межу дедлайну та часове вікно, логіку серій `IpBurstGatherer` (переривання серії,
повторні атаки, `null`-події та IP, поріг 1, неповний звіт на скінченному потоці), а також кількість
спожитих елементів, яка доводить коротке замикання.
