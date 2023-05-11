# flake8: noqa
# type: ignore

import io
import re
import json
import math
import curses
import collections
import itertools

import pylev

COLLISIONS_STR = """
escort viagra dildo
armstrong aurelius kafka luther

ampere ramses jackson
firefly policeman president

claudius executive
jihadi student princess merchant chairman doctor dentist butcher farmer
albino bush film head door saint skin

kurosawa putin
asimov

aristotle lincoln chopin donatello mendeleev catherina elizabeth

baboon cash barracuda

tiramisu
tool wine girl shirt leather paper
salt mayor chief silver orange truck farm
sheet sister brother
engineer fuel nurse bicycle bike note clock
bible koran lady  rose tape perl corset
clown witch pirate jester vampire knight bride corpse
warrior potter tiger lion
stage body darwin
bird guard gold  vega  jacket
plant seat moses wood
boat eagle widow mother parent father

bowie card
page sherlock holmes cart
font cape hair rain wife bill desk
bath ford chain
cable
fire
bond band
stone
mouse
disc
bell
ball
mail
acid
mary hole
money
phone
rocky
driver
panzer
motor
"""


WORDLIST3_STR = """
computer bicycle medicine
football
attorney cashier chopstick
broccoli

package
printer machine burrito
battery trailer cabinet
diamond samsung plastic monster
cartoon
brownie sushi donut cookie sausage
meatball potato cabbage mango cherry pepper mushroom melon carrot onion croissant
nectarine lychee olive papaya peach rhubarb pumpkin donkey

gameboy coffin
helmet unicorn
packet server
france camera engine
artist letter button cancer
square coffee plasma banner
banana burger tomato
breast guitar dollar
flower laptop branch
python dragon

shelve
bagle steak ghost
photo angel bread pizza salad
staff piano rifle pistol bullet
blanket pillow heart
album horse smith blood
pearl husky
bacon crown coupon
chair santa pilot vinyl monitor
sultan queen judge devil macbook

drug menu gate butt
foot milk cake fork
pump soap tzar
euro leaf
exit sign kiwi
"""

THINGS_STR = """
ship
hand baby
rock gift flag xbox ipod
"""

BAD_NAMES_STR = """
eminem svetlana adolf dante
joseph mark dave mike django solomon
dmitry henry kent michael william eric robert martin richard
steve scott brian matt paul jeff andrew jack george
david kelly peter frank
"""

WORDLIST3_STR += THINGS_STR
WORDLIST3_STR += COLLISIONS_STR

WORDLIST1_STR = """
diamond toilet puppet rowboat mugshot gamepad joystick
ninja  beggar iphone buffalo leibniz columbus fisherman boxer
buddha tattoo  builder simpson  rousseau  gladiator
nero caesar teacup  sergent captain lobster sinatra  gorbachev
disk  queen  camera lunatic soldier  socrates  gutenberg
radio  cheese manatee koala wambat turtle  madonna tequila  einstein sunlight  hemingway
julius tuxedo  cocktail whisky coconut mandela titanic  elephant jefferson
coffee kepler octopus tolkien  jellyfish
smith  kimono vishnu  dolphin tolstoy  umbrella  lovecraft
goat swine wolf  deputy sheriff lawyer wasabi  dracula
letter webcam  emperor othello typhoon  vladimir
medusa window  empress ulysses  keyboard watanabe
miller wizard  faraday penguin uranium  alexander salmon canvas
monkey veteran  leonardo architect bismarck fairy
dollar abraham phantom vivaldi  mechanic professor turban burqa hijab suit slippers gloves boots
mozart acrobat freddie pharaoh skywalker zepplin wallet jukebox peanut falcon shrimp
edison newton actress galileo picasso voyager  assistant spaceship
elvis zebra  orwell admiral plumber walkman  miyazaki spielberg zombie bucket
abacus parrot adviser gorilla pyramid mosquito beethoven telescope swan sparrow
hippo gandhi alcohol gymnast rainbow aquarium muhammad blueberry squid cigar
wagner pavarotti jesus hitler saddam rambo conan hepburn nixon marx lenin stalin churchill tobacco
garlic rabbit hawking augustus murderer jewel priest bishop pope dolphin otter beaver
geisha rafael android hendrix risotto musician cinnamon chocolate pigeon panther chicken
knife apollo antenna hepburn romulus bismarck nakamoto cleopatra sweater pagan snake frog lizard
artist hammer sailor asterix maradona messi ronaldo broccoli napoleon confucius satan courier mason
avocado tiara necklace rolex stein plate razor mirror beehive honey vodka diesel petrol vinegar martini
laptop boyfriend crystal troll needle mario luigi batman joker ironman rhino jigsaw feather
hubble bazooka samurai champion lambo tshirt waffle biscuit hannibal vader torch shampoo
clerk hunter spider bitcoin kennedy sisyphus raven satoshi spoon purse
redneck chemist prophet surgeon parcel balloon cowboy liver kidney brain skull diploma brick
waiter peasant officer cadet valet grunt obelix airman marshal barbie violin trumpet clarinet flute
cassette headset earpiece camel
"""


WORDLIST2_STR = """
ithaca ottawa korea dakota virginia maryland michigan chicago austria
donegal galway kildare wexford yorkshire norfolk suffolk sussex cornwall harvard stanford
mecca  latvia sicily  arizona nigeria  bulgaria pakistan  fukushima kuwait haiti
miami  bosnia lisbon algeria albania okinawa  burgundy graveyard orlando sparta tibet
cuba  milan angola auburn london baghdad germany ontario  guatemala kansas serbia
brazil madrid sweden bahrain glasgow pacific cambodia hiroshima manhattan brooklyn bronx
iraq  osaka  mexico sydney  hamburg palermo scotland  hyderabad
paris  canada monaco bangkok hungary pompeii caucasus shanghai  indonesia
castle moscow taiwan  bavaria lappland ireland shenzhen  jerusalem fairfax belize
mumbai beijing jakarta seattle namibia slovakia  liverpool calgary
spain  crimea tehran  troy iberia     belfast omaha morocco jamaica seville  tasmania
sudan  cyprus nagoya belgium somalia  damascus thailand  melbourne
turin burma syria  dublin narnia tobago  bohemia jupiter dortmund trinidad  minnesota
texas  nassau uganda  bolivia karachi toulouse  ethiopia valencia  neverland
china nevada ukraine  bristol kashmir quebec montreal toronto  helsinki yokohama uruguay
congo tokyo  france norway venice  capella kolkata tripoli  himalaya zanzibar  nuremberg
odessa vienna  cardiff lebanon tunisia  hogwarts zimbabwe  pyongyang
oregon warsaw  corsica tuscany  honduras amsterdam rotterdam
yemen  oxford zagreb  croatia adelaide honolulu serengeti
ibiza alaska ghetto zambia  memphis argentina stockholm
india gotham zurich  denmark mercury istanbul stuttgart
italy ankara havana detroit moldova atlantic kalahari baltimore tennessee
japan arabia hawaii romania dresden barcelona panama
arctic russia denver indiana britain england myanmar benjamin bucharest wisconsin
malawi kenya israel sahara estonia nairobi bordeaux mallorca catalonia
athens jordan saturn algiers nanjing botswana chernobyl
lagos beirut kosovo neptune brussels nagasaki berlin krakow florida norwich rwanda
niagara dubai bedford newport budapest normandy edinburgh wicklow cornell
alibaba redmond grenada granada houston trenton babylon aspen gambia tacoma midway
midwest toledo persia
"""

ORGANIZATIONS_STR = """
ebay nestle netflix
honda cisco nokia police unicef unesco
siemens  sony heineken atari konami nissan
yahoo  pepsi  suzuki  kodak  wikipedia
visa google adidas nike facebook baidu
disney microsoft youtube amazon hitachi paypal
boeing sanyo fujitsu toshiba
"""

PLACES_STR = """
consulate prussia america halifax
kiev alps  santiago  portugal boston  colombia ohio
munich cologne  italy idaho spain armenia antwerp andalusia
chechnya canberra barbados kinshasa anatolia callisto
alberta alabama kentucky jericho paraguay
newcastle montana marseille milwaukee york delhi nepal  poland  kyoto finland
taipei oslo malta utah  fiji hanoi kabul pluto prague saxony
bhutan dayton chile jersey gdansk egypt iowa asia iran seoul

cairo andes columbia holland europe crete rhodes assyria colorado carolina
germany florida pacific vietnam georgia africa atlanta greece
"""

WORDLIST2_STR += PLACES_STR
WORDLIST2_STR += ORGANIZATIONS_STR

WORDLIST4_STR = """
raspberry pineapple cinnamon chocolate walnut tofu yoghurt
turnip spinach  impala    artichoke crocodile barbeque
tiara parrot sinatra iphone tuxedo sushi husky kafka ronaldo asterix socrates
avocado unicorn vladimir napoleon muhammad umbrella galileo einstein mango
ninja picasso gorilla kimono pyramid spoon cigar coconut
hepburn nixon violin gameboy witch jewel penguin tomato pizza
manatee koala wambat turtle dentist dildo sherlock darwin toilet santa printer judge
mouse wizard captain cowboy jacket hitler rambo hannibal vader conan saddam coffee mirror
python stone piano hammer chair pepper salmon vodka
whisky pirate onion rolex samurai rhino elephant beaver lambo
bible diamond spider kidney buffalo donkey webcam knight dragon
lawyer flower laptop bitcoin satoshi doctor orange guitar camera kebab
octopus angel escort rabbit horse battery teacup viagra blood hummus lasagna
helmet wallet garlic mozart zombie elvis caesar fairy letter pancake popcorn
cookie liver falcon bucket eagle nurse dollar puppet keyboard ostrich pelican
broccoli burrito snake pigeon jesus buddha dracula burger panda duck
pumpkin martini tequila dolphin cassette mosquito cocktail bismarck
necklace beehive geisha macbook bishop redneck bazooka chicken button
miller smith gandhi batman aquarium bullet pillow mugshot vinyl surgeon
maradona xbox lizard devil knife lobster potato farmer gamepad balloon
carrot razor butcher banana hippo peanut raven medusa baboon sausage
turban boxer melon lenin rifle zebra feather stalin firefly walkman
bacon clock cabbage tshirt blanket photo joker koran joystick meatball
olive luther wasabi trumpet lincoln madonna donut swine bagle sweater
torch steak purse edison panther mandela mason tiger brain heart chemist
vinegar faraday hijab abacus skull squid truck troll cashier barbie otter
football shrimp rowboat salad biscuit cherry priest computer jukebox
tobacco jigsaw potter moses papaya alcohol server pistol honey coupon ampere sparrow
diesel tolkien branch packet crown needle rainbow canvas brick ironman
obama petrol leibniz rousseau luigi asimov kennedy tolstoy newton wagner kepler
gymnast augustus aurelius ulysses rhubarb zepplin headset crystal sultan
othello freddie miyazaki claudius kurosawa sisyphus earpiece tiramisu
antenna romulus peasant flute pharaoh clarinet jihadi beggar orwell mechanic
sheriff widow leonardo shampoo mayor prophet messi ghost waffle
tyson muffin chief watanabe hunter engineer plumber admiral scorpion

foot lady bell rock acid milk nero disc goat gift wolf cake soap
swan euro wine fire tzar perl cape baby boat kiwi frog flag rose pearl
marx pope girl tape suit confucius monkey jellyfish
father mother vivaldi spielberg motor bride pilot obelix mario

bicycle aquarium augustus aurelius bismarck broccoli cassette
clarinet claudius cocktail columbus computer earpiece einstein elephant engineer
football joystick keyboard kurosawa leonardo maradona meatball mechanic
miyazaki mosquito muhammad murderer mushroom nakamoto napoleon
necklace princess rousseau sisyphus socrates tiramisu
umbrella vladimir watanabe

photo      computer   obama      server     messi      lambo      gift       heart
smith      baby       satoshi    camera     blood      rock       bitcoin    horse
fire       chief      button     coffee     letter     printer    bible      chair
stone      guitar     jesus      crystal    santa      wine       motor      judge
xbox       laptop     alcohol    orange     father     truck      mouse      brain
football   doctor     dollar     battery    angel      clock      diamond    rose
viagra     buffalo    acid       flower     knight     captain    disc       flag
dildo      boat       engineer   vinyl      lawyer     tape       pilot      bishop
keyboard   lady       miller     piano      euro       bell       eagle      crown
columbus   nurse      mirror     pizza      mayor      ghost      potter     webcam
python     lincoln    devil      cowboy     tiger      jacket     dragon     cherry
liver      cake       packet     diesel     tobacco    cassette   escort     wizard
kennedy    elvis      olive      honey      necklace   wolf       cookie     mason
salad      brick      priest     newton     buddha     snake      rabbit     monkey
farmer     rainbow    spider     pepper     witch      toilet     fairy      saddam
madonna    bicycle    dentist    needle     kidney     dolphin    onion      beaver
elephant   duck       violin     jewel      frog       darwin     pyramid    coconut
garlic     holmes     moses      purse      hammer     bullet     skull      bacon
cocktail   rifle      steak      shrimp     pumpkin    tomato     einstein   shampoo
helmet     banana     penguin    ninja      sheriff    squid      raven      flute
wallet     turtle     umbrella   mechanic   rolex      sushi      zombie     balloon
sausage    admiral    cigar      spoon      barbie     jukebox    nixon      jigsaw
goat       falcon     razor      torch      boxer      zebra      panda      geisha
pirate     blanket    swan       mushroom   bucket     muhammad   napoleon   samurai
mozart     pelican    vladimir   petrol     gameboy    freddie    hitler     caesar
tuxedo     spinach    gorilla    mosquito   rhino      vodka      edison     gandhi
donkey     popcorn    burger     muffin     pigeon     panther    parrot     troll
tyson      puppet     whisky     octopus    feather    lobster    husky      lizard
pineapple  kiwi       plumber    redneck    joystick   carrot     sinatra    otter
picasso    galileo    tequila    sherlock   scorpion   tolkien    joker      leonardo
hippo      avocado    raspberry  vader      melon      ironman    tshirt     beehive
sparrow    crocodile  ostrich    impala     stalin     manatee    lenin      hannibal
spielberg  abacus     koran      koala      unicorn    tofu       asterix    yoghurt
rambo      gymnast    teacup     kimono     artichoke  ronaldo    confucius  jihadi
meatball   maradona   iphone     wambat
"""

WORDLIST4_STR += """
photo      computer   obama      server     messi      lambo      heart      gift
baby       smith      satoshi    blood      rock       camera     horse      fire
bitcoin    chief      button     bible      letter     chair      stone      jesus
motor      santa      coffee     printer    antenna    judge      crystal    brain
laptop     chocolate  father     xbox       guitar     orange     alcohol    dollar
angel      battery    flower     disc       diamond    flag       dildo
acid       pilot      viagra     lawyer     buffalo    hunter
captain    piano      miller     crown      euro       eagle      bell       pizza
mirror     ghost      knight     devil      tiger      python     bishop     columbus
jacket     engineer   dragon     lincoln    webcam     keyboard   cherry     diesel
elvis      honey      olive      escort     tobacco    mario      mason      wizard
salad      cookie     wolf       bride      canvas     coupon     kennedy    soap
snake      witch      newton     rabbit     toilet     cowboy     pepper     buddha
spider     rainbow    saddam     cinnamon   onion      kidney     cassette   needle
mosquito   jewel      bicycle    moses      madonna    violin     darwin     dentist    holmes
necklace   skull      bullet     hammer     steak      garlic     ninja      raven
pyramid    potato     shrimp     squid      walnut     flute      rolex
banana     turtle     penguin    spoon      sheriff    sushi      pumpkin
shampoo    zombie     prophet    barbie     razor      torch      boxer
balloon    elephant   jigsaw     admiral    falcon     coconut    zebra
pirate     jukebox    blanket    geisha     mozart     trumpet    hepburn
samurai    rhino      petrol     murderer   einstein   peanut     caesar     vodka
pelican    mushroom   gameboy    tuxedo     edison     freddie    sausage    umbrella
mechanic   gandhi     gorilla    burger     pistol     troll      popcorn
pigeon     parrot     muffin     husky      cabbage    muhammad
napoleon   luigi      vladimir   lobster    kiwi       octopus
sinatra    vader      picasso    hippo      galileo    pineapple
broccoli   tequila    socrates   sultan     avocado    lenin
tshirt     stalin     beehive    plumber    pharaoh
macbook    ostrich    raspberry  koala      joystick   waffle     manatee
abacus     donut      jellyfish  tofu       unicorn    scorpion   hannibal
ironman    rousseau   papaya     kafka      asterix    medusa
yoghurt    wasabi     pancake    lasagna    kimono     teacup     bazooka    gymnast
beggar     zepplin    mugshot    leibniz    miyazaki   artichoke  ronaldo
kebab      kurosawa   sisyphus   earpiece   hummus     obelix
tiramisu   nakamoto   meatball   rowboat    iphone     wambat

bacon      beaver     boat       brick      bucket     cake       carrot     cigar
clock      cocktail   confucius  crocodile  doctor     dolphin    donkey     duck
fairy      farmer     feather    football   frog       goat       helmet     hitler
joker      kangaroo   lady       liver      lizard     mayor      melon      monkey
mosquito   mouse      nixon      nurse      otter      packet     panda      panther
priest     puppet     purse      rambo      rifle      rose       sherlock   sparrow
spinach    swan       tomato     truck      tyson      wallet     whisky     wine
"""

WORDLIST5_STR = """
youtube    uruguay    suffolk    vietnam    norfolk    gdansk     yahoo      ebay
texas      fujitsu    oxford     china      pacific    canada     google
japan      london     italy      belgium    france     europe
england    nokia      siemens    mexico     egypt      paypal     germany
cyprus     seattle    kashmir    paris      mercury    police     florida
america    sony       midwest    africa     jersey     amazon
denmark    ireland    miami      boston     israel
cisco      sydney     korea      newport    iraq       asia       houston    ohio
kansas     disney     memphis    idaho      greece     jupiter    oregon     suzuki
brazil     georgia    hawaii     ukraine    ontario    sweden     russia
quebec     dakota     arizona    dublin     alaska     honda      beijing
glasgow    indiana    toshiba    toronto    tokyo      iowa       finland
jordan     nevada     utah       morocco    hungary    kenya      delhi      taiwan
detroit    nepal      visa       berlin     orlando    kodak      austria
athens     congo      cologne    omaha      cardiff    kuwait     lebanon
sudan      malta      ottawa     montana    syria      moscow     baghdad
sussex     haiti      venice     milan      prague     holland    madrid
yemen      cuba       nissan     arctic     alberta    hamburg    wexford    nike
rhodes     munich     panama     arabia     kyoto      sanyo
auburn     calgary    adidas     aspen      bolivia    dayton     ghetto     estonia
fairfax    uganda     latvia     fiji       myanmar    netflix    croatia    tobago
hitachi    atari      saturn     bronx      cairo      zambia     nigeria    burma
mumbai     troy       angola     romania    tibet      jamaica    tunisia
seoul      capella    bhutan     halifax    rwanda     toledo     redmond    moldova
boeing     zurich     serbia     namibia    kosovo     pluto
unesco     bahrain    crete      lisbon     warsaw     gambia
seville    sahara     niagara    ibiza      osaka      tacoma     babylon
armenia    tuscany    pepsi      algeria    sicily     antwerp
oslo       somalia    unicef     nassau     narnia     galway     alibaba    dresden
jakarta    hanoi      ithaca     donegal    tehran     trenton    pompeii
havana     mecca      kabul      gotham     lagos      palermo    alps       persia
odessa     karachi    nairobi    nestle     andes      zagreb     granada    kildare
tripoli    nanjing    kiev       prussia    krakow     sparta     konami     ankara
nagoya     okinawa    iberia     kolkata    bohemia    saxony     bavaria    corsica
crimea     assyria    belfast    baidu      wicklow
adelaide anatolia atlantic barbados benjamin bordeaux botswana brooklyn
brussels budapest bulgaria burgundy callisto cambodia canberra carolina
caucasus chechnya colorado columbia cornwall damascus dortmund
ethiopia facebook heineken helsinki himalaya hogwarts honduras honolulu
istanbul kalahari kentucky kinshasa mallorca maryland michigan
montreal nagasaki normandy pakistan paraguay portugal
santiago scotland shanghai shenzhen slovakia stanford tasmania thailand
toulouse trinidad valencia virginia yokohama zanzibar zimbabwe
"""

WORDLIST5_STR = """
europe     google     germany    florida    oxford     pacific    cyprus     quebec
police     france     amazon     canada     virginia   belgium    london     carolina
suzuki     israel     egypt      denmark    detroit    oregon     vietnam    paypal
columbia   mercury    brazil     ukraine    disney     microsoft  africa     lebanon
mexico     rhodes     yahoo      texas      kentucky   ghetto     newport    kansas
estonia    boston     bangkok    sydney     pakistan   uruguay    arizona    fujitsu
china      ontario    myanmar    portugal   greece     hawaii     atlanta    dakota
alaska     russia     england    athens     baghdad    castle     india      moldova
ebay       nevada     georgia    madrid     odessa     prague     suffolk    sweden
dublin     kuwait     britain    montana    jordan     adidas     japan      gotham
sussex     zimbabwe   arctic     seattle    taiwan     ireland    botswana   honolulu
norway     stanford   toronto    tuscany    spain      italy      krakow     berlin
nokia      trinidad   alberta    zagreb     brussels   shanghai   ethiopia
anatolia   hungary    kashmir    adelaide   glasgow    uganda     paris      cornwall
toledo     moscow     melbourne  harvard    maryland   scotland   orlando    boeing
ottawa     delhi      austria    nigeria    siemens    istanbul   warsaw     edinburgh
budapest   latvia     miami      angola     dayton     auburn     morocco    mumbai
unesco     bolivia    cisco      korea      antwerp    manhattan  netflix    venice
santiago   valencia   sony       palermo    helsinki   arabia     liverpool  idaho
tunisia    kosovo     hitachi    munich     croatia    finland    guatemala  jerusalem
kolkata    hamburg    tacoma     zambia     gdansk     calgary    iraq       halifax
thailand   bordeaux   ohio       sicily     serbia     asia       fairfax    lisbon
jamaica    beijing    tokyo      stockholm  toulouse   holland    romania    shenzhen
sahara     babylon    cambodia   iowa       ithaca     nepal      bulgaria   slovakia
damascus   utah       kyoto      congo      yemen      tehran     omaha      dresden
galway     chechnya   narnia     bahrain    malta      pluto      zanzibar   sudan
pompeii    haiti      unicef     argentina  yokohama   armenia    milan      nairobi
caucasus   tibet      bronx      havana     konami     burma      seville    dortmund
aspen      hogwarts   karachi    jakarta    trenton    seoul      nike       nagasaki
cuba       kabul      cairo      atari      fiji       ankara     crete      kalahari
okinawa    himalaya   troy       tasmania   bohemia    ibiza      nanjing
crimea     youtube    lagos      mecca      facebook   bavaria    kiev       kinshasa
algeria    america    barcelona  belfast    brooklyn   colorado   hanoi
barcelona  houston    michigan
namibia    nassau     osaka      oslo       panama     persia
rwanda     saxony     somalia    syria      visa
zurich
"""

WORDLIST6_STR = """
toyota citroen renault peugeot yamaha porsche mercedes
samsung hyundai intel ford nintendo dell acer asus sega
canon

present origami tsunami
reporter desk staff
deputy engine card paper note queen hubble artist

plane table space field metro hill store ocean river coast sirius academy street
peak void station volvo java train carpet path road tree
fort soil chad xerox bottle floor ferrari
club city palm town safe shop cafe moon house movie kingdom room port
island iceland home hall board company sixties embassy
studio earth garden museum punjab library beach valley eighties
hospital bridge mountain park    lake       forest temple     bank
stadium turkey pocket basket theatre pool campus village ground school hotel
church office court bedroom kitchen factory cinema volcano
podium garage harbor casino villa balcony airport meadow patio swamp disco jungle
"""


WORDLIST1 = list(sorted(re.findall(r"[a-z]+", WORDLIST1_STR)))
WORDLIST2 = list(sorted(re.findall(r"[a-z]+", WORDLIST2_STR)))
WORDLIST3 = list(sorted(re.findall(r"[a-z]+", WORDLIST3_STR)))
WORDLIST4 = list(sorted(re.findall(r"[a-z]+", WORDLIST4_STR)))
WORDLIST5 = list(sorted(re.findall(r"[a-z]+", WORDLIST5_STR)))
WORDLIST6 = list(sorted(re.findall(r"[a-z]+", WORDLIST6_STR)))


def check_things():
    i = 0
    for w in set(WORDLIST1) - set(WORDLIST4):
        if len(w) > 8:
            continue
        i += 1
        if i % 9 == 0:
            print()
        print(w.ljust(9), end=" ")
    print()


# check_things()


def read_word_frequencies():
    # http://norvig.com/ngrams/
    # http://norvig.com/ngrams/count_1w.txt
    with io.open("wordlists/count_1w.txt", mode="r", encoding="utf-8") as fobj:
        lines = iter(fobj)
        rows  = [line.strip().split("\t", 1) for line in lines]

    result = {word: int(freq.strip()) for word, freq in rows}
    # dataset is from 2006, so some newer and words are added manually
    result.update(
        {
            'obama'  : 100000000,
            'trump'  : 100000000,
            'messi'  : 100000000,
            'satoshi': 100000000,
            'lambo'  : 100000000,
            'bitcoin': 100000000,
            'corona' : 100000000,
        }
    )
    return result


def pretty_wordlists(wordlist, min_len, max_len, label):
    word_frequencies = read_word_frequencies()
    distances        = load_distances(wordlist)

    for word in wordlist:
        if word not in word_frequencies:
            word_frequencies[word] = 1

    def freq_key(word):
        n = math.log(word_frequencies[word])
        return -n

    def penaulty(word):
        c = sum(1 for w in wordlist if word[:3] in w)
        l = abs(7.5 - len(word))
        n = 1 / math.log(word_frequencies[word])
        d = sum(1 for w in wordlist if distances[w + ":" + word] < 5)
        p = c * 20.0 + l * 2.0 + n * 0.0 + d * 0.0
        # print(f"{word:>9} {c * 20.0:9.2f} {l * 2.0:9.2f} {d * 0.0:9.2f} {p}")
        return p

    # lower penaulty -> better choice
    wordlist = list(sorted(wordlist, key=penaulty))

    words_by_prefix = collections.defaultdict(list)
    for word in wordlist:
        if min_len <= len(word) <= max_len:
            words_by_prefix[word[:3]].append(word)

    filtered_wordlist = []

    for word in wordlist:
        if min_len <= len(word) <= max_len:
            collisions = [
                fword
                for fword in filtered_wordlist
                if fword != word and (fword[:3] in word or word[:3] in fword or distances[fword + ":" + word] < 3)
            ]
            if not any(collisions):
                filtered_wordlist.append(word)

    # for word in sorted(filtered_wordlist):
    #     if len(words_by_prefix[word[:3]]) == 1:
    #         aligned_words = [w.ljust(9) for w in words_by_prefix[word[:3]] if w != word]
    #         print(word.ljust(9), " ".join(aligned_words))

    # scores_by_word = {w: score(w) for w in filtered_wordlist}
    # _wordlist_diff(scores_by_word, label=label)
    # _pretty_wordlist(filtered_wordlist, label=label, words_per_line=16)

    print()
    print(label, len(filtered_wordlist))
    print()
    return list(sorted(filtered_wordlist[:256]))


def _wordlist_diff(scores_by_word, label):
    wordlist = sorted(list(scores_by_word)[:256], key=len)

    path = f"/tmp/old_wordlist_{label}.txt"
    try:
        with open(path, mode="r") as fobj:
            old_words = set(fobj.read().split(" "))
    except:
        old_words = set()

    new_words     = set(wordlist) - old_words
    removed_words = old_words - set(wordlist)

    with open(path, mode="w") as fobj:
        fobj.write(" ".join(wordlist))

    print()
    print("old words", " ".join(removed_words))
    print("new words", " ".join(new_words    ))
    print()


def _pretty_wordlist(wordlist, label, words_per_line=8):
    for i, word in enumerate(wordlist):
        print(f"{word:<9} ", end=" ")
        # s = scores_by_word[word]
        # print(f"{word:<9} {s:5.2f}", end=" ")
        if (i + 1) % words_per_line == 0:
            print()
            if (i + 1) % 256 == 0:
                print()

    return

    num_rows = int(len(scores_by_word) / 8) + 1
    cols     = [[] for _ in range(8)]
    for i, word in enumerate(scores_by_word):
        col_idx = i // num_rows
        cols[col_idx].append(word)

    for row in range(num_rows):
        for col in cols:
            l = len(col[-1])
            if row < len(col):
                word = col[row]
                s    = scores_by_word[word]
                print(f"{word:>9} {s:5.2f}", end=" ")
        print()

    print()


def load_distances(wordlist):
    cache_path = "/tmp/word_distances_cache.json"
    try:
        with io.open(cache_path, mode="r", encoding="utf-8") as fobj:
            distances = json.loads(fobj.read())
    except:
        distances = {}

    word_frequencies = read_word_frequencies()

    for w1 in wordlist:
        for w2 in wordlist:
            keya = w1 + ":" + w2
            keyb = w2 + ":" + w1
            if w1 == w2:
                distances[keya] = 0
                distances[keyb] = 0
            elif keya not in distances:
                d = pylev.damerau_levenshtein(w1, w2)
                distances[keya] = d
                distances[keyb] = d

    with io.open(cache_path, mode="w", encoding="utf-8") as fobj:
        fobj.write(json.dumps(distances))

    return distances


def show_distances(wordlist, threshold=2):
    word_frequencies = read_word_frequencies()
    freq             = {w: math.log(n) for w, n in word_frequencies.items()}
    distances        = load_distances(wordlist)

    clashes = []
    for i, w1 in enumerate(wordlist):
        for w2 in wordlist[i + 1 :]:
            key = w1 + ":" + w2
            d   = distances[key]
            if not 0 < d < threshold:
                continue
            wa, wb = key.split(":")
            fa     = freq[wa]
            fb     = freq[wb]
            fdelta = -abs(fa - fb)
            clashes.append((fdelta, d, wa, wb))

    clashes.sort()

    for i, (fdelta, d, wa, wb) in enumerate(clashes):
        print(f"{wa:>10} {wb:>10} {d} {-fdelta}")
        if i > 1000:
            break


def common_prefixes(wordlist, prefix_len):
    word_frequencies = read_word_frequencies()
    freq             = {w: math.log(n) for w, n in word_frequencies.items()}
    prefix_words     = collections.defaultdict(list)
    for word in wordlist:
        prefix_words[word[:prefix_len]].append(word)

    for words in prefix_words.values():
        if len(words) == 1:
            continue
        words = sorted(words, key=lambda w: -freq[w])
        w1, w2 = words[:2]
        fdelta = abs(freq[w1] - freq[w2])
        print(w1, w2, f"{freq[w1]:5.2f} {freq[w2]:5.2f} ")


def yayornay_words():
    word_frequencies = read_word_frequencies()
    word_items       = iter(word_frequencies.items())

    results_path = "/tmp/word_choices.json"

    try:
        with io.open(results_path, mode="r", encoding="utf-8") as fobj:
            results = json.loads(fobj.read())
    except:
        results = {}

    stdscr = curses.initscr()
    stdscr.clear()
    curses.noecho()
    curses.cbreak()
    stdscr.keypad(True)
    KEY_F = 102
    KEY_J = 106
    KEY_K = 107
    try:
        last_word = list(results)[-1]
        word, n = next(word_items)
        while True:
            is_candidate_word = (
                4 <= len(word) <= 9
                and word not in results
                and not word.endswith("ing")
                and not (word.endswith("ish") and word[:-3] in word_frequencies)
                and not (word.endswith("ed" ) and word[:-2] in word_frequencies)
                and not word[-1] == "s"
                and word[:-1] in word_frequencies
            )
            if not is_candidate_word:
                word, n = next(word_items)
                continue

            stdscr.clear()
            stdscr.addstr(f"\n\n {last_word:<11} {results[last_word]}")
            stdscr.addstr(f"\n\n {word:<11} ")
            ch = stdscr.getch()

            if ch == KEY_J:
                results[word] = 1
                stdscr.addstr(f"1")
                last_word = word
                word, n = next(word_items)
            elif ch == KEY_F:
                results[word] = 0
                stdscr.addstr(f"0")
                last_word = word
                word, n = next(word_items)
            elif ch == KEY_K:
                results[last_word] = (results[last_word] + 1) % 2
            else:
                break
    except KeyboardInterrupt:
        pass
    finally:
        curses.nocbreak()
        stdscr.keypad(False)
        curses.echo()
        curses.endwin()

        results_data = json.dumps(results)
        with io.open(results_path, mode="w", encoding="utf-8") as fobj:
            fobj.write(results_data)


VERBS = """
accept accuse achieve acknowledge acquire adapt add adjust admire admit
adopt adore advise afford agree aim allow announce anticipate apologize
appear apply appreciate approach approve argue arise arrange arrive
ask assume assure astonish attach attempt attend attract avoid awake
bake bathe be bear beat become beg begin behave believe
belong bend bet bind bite blow boil borrow bounce bow
break breed bring broadcast build burn burst buy calculate
can could care carry catch celebrate change choose chop claim
climb cling come commit communicate compare compete complain complete concern
confirm consent consider consist consult contain continue convince cook cost
count crawl create creep criticize cry cut dance dare
deal decide defer delay deliver demand deny depend describe deserve
desire destroy determine develop differ disagree discover discuss dislike distribute
dive do doubt drag dream drill drink drive drop dry
earn eat emphasize enable encourage engage enhance enjoy ensure
entail enter establish examine exist expand expect experiment explain xplain everything.
explore extend fail fall feed feel fight find finish
fit fly fold follow forbid forget forgive freeze fry
generate get give go grind grow hang happen hate
have hear hesitate hide hit hold hop hope hug hurry
hurt identify ignore illustrate imagine imply impress improve include
incorporate indicate inform insist install intend introduce invest investigate involve
iron jog jump justify keep kick kiss kneel knit
know lack laugh lay lead lean leap learn leave
lend lie lift light lie like listen look lose love
maintain make manage matter may mean measure meet melt
mention might mind miss mix mow must need neglect negotiate
observe obtain occur offer open operate order organize ought to
overcome overtake owe own paint participate pay peel perform
persuade pinch plan play point possess postpone pour practice prefer
prepare pretend prevent proceed promise propose protect prove pull punch pursue push
put qualify quit react read realize recall receive recollect recommend
reduce refer reflect refuse regret relate relax relieve rely remain
remember remind repair replace represent require resent resist retain
retire rid ride ring rise risk roast run sanction satisfy say scrub see seem sell
send serve set settle sew shake shall shed shine shoot should show shrink
shut sing sink sit ski sleep slice slide slip smell snore solve sow
speak specify spell spend spill spit spread squat stack stand start steal stick
sting stink stir stop stretch strike struggle study submit succeed suffer suggest supply
suppose surprise survive swear sweep swell swim swing take talk taste teach
tear tell tend think threaten throw tiptoe tolerate translate try understand vacuum
value vary volunteer wait wake walk want warn wash watch wave wear
weep weigh whip will win wish would write
"""

ADVERBS = """
accept achieve act add adjust admire advise amass amazed amuse annoy approach attend attract avoid
believe blacken bleed bore bother breathe bury care challenge chase
cheer choose clear collect comfort complex confuse consider console continue
craze create credit cure curse damage deafen decide decorate delight
demand derive deserve destroy develop die differ disturb dust educate
embarrass empower empty encircle encourage endanger enthuse enumerate envy evaporate
expect explain explore fascinate feed firm fly force glorify grow
harm hate heal hope identify imitate impress include indicate inform
inhabit injure inquire instruct insult intent interfere introduce invent irritate
lead live lose madden migrate modernise moisten monotonies move narrow
nationalise observe own perform permit persuade please popularise quicken redden
sadden secure see speed whiten acceptable achievable active additional adjustable
admirable advisable massive amazing amusing annoying approachable attentive attractive avoidable
believable black bloody boring bothering breathing buried careful challenging chasing
cheerful chosen collective comfortable confused considerable consoled continuous crazy creative
creditable curable cursed damaged deaf decisive decorative delightful demanding derivative
deserving destructive developing dead different disturbing dusty educative embarrassing powerful
circular courageous dangerous enthusiastic numerable envious evaporating expected explainable exploring
fascinating flying forceful glorious growing harmful hateful healthy hopeful indentified
indentifying imitative impressive inclusive indicative informative inhabitant injurious inquiring
instructive insulting intentional interfering introductory inventive irritating leading lively alive
lost mad migrating modern moistures monotonous movable national observatory performing
permissible persuasive pleasant popular quick red sad secured scenic seen speedy
white bad actively massively carefully cheerfully clearly collectively comfortably
considerably continuously crazily creatively creditably delightfully destructively
differently powerfully circularly courageously dangerously enviously expectedly firmly
forcefully gloriously growingly harmfully hatefully healthily hopefully imitatively
impressively inclusively indicatively injuriously insultingly intentionally irritatingly
leadingly livingly madly monotonously movingly nationwide quickly sadly securely speedily badly
"""

SHITLIST = """
mosquito
# too general
animal
land
place
region world
state planet
county
lord dean worker leader  employee manager
analyst minister investor
citizen director
root
wall
# ambiguous
turkey
swallow
apple
hilton
general
# zodiac
pisces gemini
virgo taurus
# too big
armada army
# abstract
"""

ABSTRACT_NOUNS = """
surface plug face zone cell lane
team uncle daughter husband
internet website firefox email linux  unix
steel metal market image author person human family video
ability adoration advantage adventure amazement anger annoyance anxiety appetite
apprehension artisty awareness awe beauty belief bravery brilliance brutality
woman women calm care chaos charity childhood clarity cleverness coldness comfort
communication compassion confidence confusion contentment courage crime curiosity customer service
death deceit dedication defeat delay delight despair determination dexterity
dictatorship disappointment disbelief dishonesty disquiet disregard disturbance divorce dream
education ego elegance envy evil failure faith fascination fear
fiction fragility freedom friendship gain generation generosity goal goodness
gossip growth happiness hate hatred hope horror hurt idea
infancy infatuation inflation insanity intelligence irritation joy justice kindness
laughter law liberty lie life loneliness loss love luck
luxury maturity mercy movement music nap need opinion opportunity
pain patience peace peculiarity perseverance pleasure poverty power pride
principle reality relaxation relief religion restoration riches right rumour
sacrifice sanity satisfaction self-control sensitivity service shock silliness skill
sleep sorrow speed strenght strictness success surprise talent thrill
timing tiredness tolerance trend trust uncertainty unemployment union unreality
victory wariness warmth weakness wealth weariness wisdom wit worry friend
"""

SHITLIST = set(sorted(re.findall(r"[a-z]+", VERBS + ADVERBS + ABSTRACT_NOUNS)))


def generate_filtered():
    word_frequencies = read_word_frequencies()
    word_items       = iter(word_frequencies.items())
    with io.open("wordlists/unigram_freq_filtered.tsv", mode="w", encoding="utf-8") as fobj:
        fobj.write("word\tcount\n")
        for word, n in word_items:
            is_candidate_word = (
                5 <= len(word) <= 8
                # and word not in results
                and word not in ALL_WORDS
                and word not in SHITLIST
                and not word.endswith("ing")
                and not (word.endswith("ish") and word[:-3] in word_frequencies)
                and not (word.endswith("ed" ) and word[:-2] in word_frequencies)
                and not (word[-1] == "s" and word[:-1] in word_frequencies)
            )
            if is_candidate_word:
                fobj.write(f"{word:<9} {math.log(n):.2f}\n")


SHITLIST_STR_V1 = """
harbor sheet board ground punjab
ocean tacoma halifax    garden     bedroom    square field
burgundy   valencia slovakia
store hungary
myanmar sirius cornell company lychee cornwall nanjing
flute houston wicklow galway
staff michigan
court fujitsu
europe     dakota     carolina   oregon
adelaide knight
midwest toulouse
augustus
kosovo
munich mumbai
latvia
zambia monitor
unicef
zagreb
maryland atlanta
marshal clerk
prussia
bolivia
sixties
sussex
calgary
malta santiago
mallorca
moldova
adviser
meadow
eighties
ithaca
donegal impala
krakow hepburn rafael bulgaria
kolkata lebanon bordeaux bohemia
ulysses
murderer
zanzibar
beach
table
dortmund

scotland
kentucky kenya
chain chair chairman
mercury merchant
torch
ninja
satan
colorado cologne
bristol ninja portugal
mountain antwerp
claudius romulus
earpiece earth
saturn
sergent vinyl
canberra madrid
kinshasa salad
packet pacific
england engineer
printer priest
airman newport
honolulu  honda     honduras
bangkok   banner
brooklyn  brownie   brother   bronx
hitachi   warsaw
station   stadium   stanford  stage
botswana heart
shenzhen  sherlock  shelve valet
album     albania   alberta
barbados  barbie battery
campus    cambodia  camel
museum    musician
helsinki cinnamon serbia
mecca officer cancer    canvas    canon volvo serbia
santa sanyo studio papaya cinnamon
beirut spinach moscow    moses florida   floor
china     chile     chief     chicken
medicine dracula bismarck  biscuit
villa redmond
algiers   andes
tolkien   toledo
burrito   burqa     burma
kansas jersey hanoi
samsung manatee   mandela
plastic   plate     plasma    plant
jacket unesco
spain     sparta    space
bride     britain   brick
indiana moscow    moses
spinach columbia  columbus
hawking shampoo
angola    lappland
casino    cassette  cashier   alabama potter
pearl     peach     peasant
machine   pillow bagle kabul lunatic cisco alibaba
walkman ramses   facebook     wallet
phantom nagoya
dollar babylon jackson memphis
gamepad   gambia
fairfax cocktail skull
budapest dublin
cabinet   cabbage
turin     turnip    turtle    turban
disney
belgium   belize
montana   monaco    monster   montreal  money
quebec
truck
taipei tobago
normandy  norwich   norfolk
denmark   denver
cartoon   carpet    cardiff
vienna
capella trailer
cheese    chechnya  chemist
"""

ALL_WORDS = set(WORDLIST1 + WORDLIST2 + WORDLIST3 + WORDLIST4 + WORDLIST5 + WORDLIST6)

PLACES = WORDLIST2
THINGS = ALL_WORDS - set(PLACES)

# check for duplicates
# assert len(ALL_WORDS) == len(WORDLIST1) + len(WORDLIST2)

def read_wordlist(filepath):
    with io.open(filepath, mode="r", encoding="utf-8") as fobj:
        text = fobj.read()
    return list(sorted(re.findall(r"[a-z]+", text)))


ALL_WORDS2 = read_wordlist("wordlists/en_wordlist.txt")
# _pretty_wordlist(sorted(set(ALL_WORDS2)), "all words")


def show_candidates():
    candidates = read_wordlist("wordlists/shitlist.txt")

    chars = "abcdefghijklmnopqrstuvwxyz"
    missing_prefixes = set(a + b + c for a, b, c in itertools.product(chars, chars, chars))

    for word in ALL_WORDS2:
        if word[:3] in missing_prefixes:
            missing_prefixes.remove(word[:3])

    for word in candidates:
        if word[:3] in missing_prefixes:
            print(word)


def main():
    # generate_filtered()
    # yayornay_words()
    # pretty_wordlists(WORDLIST4, min_len=4, max_len=9, label="things")
    # pretty_wordlists(WORDLIST5, min_len=4, max_len=9, label="places")
    chosen_words = pretty_wordlists(set(ALL_WORDS2), min_len=5, max_len=8, label="all")
    _pretty_wordlist(chosen_words, label="all", words_per_line=8)

    # print(len(NEW_WORDS))
    # show_distances(sorted(ALL_WORDS), threshold=3)
    # common_prefixes(sorted(ALL_WORDS), prefix_len=3)
    # common_prefixes(WORDLIST1, prefix_len=3)
    # common_prefixes(WORDLIST2, prefix_len=3)
    # show_distances(WORDLIST1, threshold=4)
    # show_distances(WORDLIST2, threshold=4)
    return

    wordlists        = set(WORDLIST1 + WORDLIST2)
    i                = 0
    word_frequencies = read_word_frequencies()
    for word, n in word_frequencies.items():
        if len(word) != 6:
            continue
        if word.endswith("ing"):
            continue
        if word.endswith("ish") and word[:-3] in word_frequencies:
            continue
        if word.endswith("ed") and word[:-2] in word_frequencies:
            continue
        if word in wordlists:
            continue
        is_plural = word[-1] == "s" and word[:-1] in word_frequencies
        if is_plural:
            continue
        freq = math.log(n)
        if freq < 16:
            break
        # print(f"{word:>5} {freq:5.2f}", end=" ")
        print(f"{word:>8}", end=" ")
        i += 1
        if i % 20 == 0:
            print()


if __name__ == '__main__':
    main()
