#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mem.h>

#define b 3 //faktor baketrianja, broj slogova u baketu
#define B 7 //broj baketa
#define k 1 //fiksni korak k
#define Q B*b   //ukupan broj lokacija

typedef struct
{
    int dan, mjesec, godina;
} Datum;

typedef struct
{
    int sekund, minut, sat;
} Vrijeme;

typedef struct
{
    long evidencioni_broj;
    char ime_i_prezime_spasenog[60];
    Datum datum;
    Vrijeme vrijeme;
    char oznaka_spasioca[5];
    int trajanje_spasavanja;
    int status;
    //0 - inicijalno slobodna lokacija
    //1 - lokacija koja sadrzi aktuelni slog
    //9 - lokacija koja sadrzi neaktuelan slog (logicki obrisan)

} Plaza;

typedef struct
{
    Plaza slog[b];
} Baket;

FILE* serijska = NULL;
FILE* aktivna = NULL;
char *ime_serijske = "serijska";
char ime_aktivne[20];

void formiranje_prazne_datoteke();
void izbor_aktivne_datoteke();
void prikaz_naziva_aktivne_datoteke();
void upis_novog_sloga_u_pomocnu_serijsku_datoteku();
void linearno_trazenje(FILE*, long int , int*, int*, int*, int*, Baket*);
void formiranje_aktivne_datoteke();
void prikaz_svih_slogova_aktivne_datoteke();
void logicko_brisanje_aktuelnog_sloga_iz_aktivne_datoteke();
void promjena_vrijednosti_obiljezja_datum_i_vrijeme_spasavana();

Plaza slog;
Baket baket;

int main()
{
    int meni;

    do
    {
        printf("\n\t\t** GRADSKA PLAZA **\n\n");
        printf("1. Formiranje prazne datoteke\n");
        printf("2. Izbor aktivne datoteke\n");
        printf("3. Prikaz naziva aktivene datoteke\n");
        printf("4. Upis novog sloga u pomocnu serijsku datoteku\n");
        printf("5. Formiranje aktivne datoteke citanjem sadrzaja iz pomocne serijske\n");
        printf("6. Prikaz svih slogova aktivne datoteke\n");
        printf("7. Logicko brisanje aktuelnog sloga iz aktivne datoteke\n");
        printf("8. Promjena vrijednosti obiljezja datum i vrijeme spasavanja\n");
        printf("9. Izlaz\n");

        printf("\nIzaberite opciju >> ");
        scanf("%d", &meni);
        getchar();

        switch(meni)
        {
            case 1:
                formiranje_prazne_datoteke();
                break;

            case 2:
                izbor_aktivne_datoteke();
                break;

            case 3:
                prikaz_naziva_aktivne_datoteke();
                break;

            case 4:
                upis_novog_sloga_u_pomocnu_serijsku_datoteku();
                break;

            case 5:
                formiranje_aktivne_datoteke();
                break;

            case 6:
                prikaz_svih_slogova_aktivne_datoteke();
                break;

            case 7:
                logicko_brisanje_aktuelnog_sloga_iz_aktivne_datoteke();
                break;

            case 8:
                promjena_vrijednosti_obiljezja_datum_i_vrijeme_spasavana();
                break;

            case 9:
                break;

            default:
                printf("Pogresan unos!\n");
                break;
        }

    } while(meni!=9);

    if(aktivna != NULL)
        fclose(aktivna);

    fclose(serijska);

    return 0;
}

void formiranje_prazne_datoteke()
{
    int r, q;

    printf("\nUnesite ime datoteke koju zelite da kreirate: ");
    gets(ime_aktivne);

    if((aktivna = fopen(ime_aktivne, "r+b")) != NULL)
    {
        printf("Datoteka %s vec postoji!\n", ime_aktivne);
        fclose(aktivna);
        return;
    }

    if( (aktivna = fopen(ime_aktivne, "w+b")) == NULL )
    {
        printf("Datoteka nije kreirana!\n");
        return;
    }

    r=1;

    while(r<=B) //Q //prolazim kroz bakete
    {
        q = 1;

        while(q<=b) //prolazim kroz slogove unutar baketa
        {
            memset(&baket.slog[q-1], 0, sizeof(Plaza));
            //baket.slog[q-1].evidencioni_broj='*';
            q+=1;
        }

        fwrite(&baket, sizeof(Baket), 1, aktivna);  //upisujem jedan baket u aktivnu datoteku
        r+=1;
    }

    printf("Datoteka %s je kreirana.\n", ime_aktivne);

    fclose(aktivna);
}

void izbor_aktivne_datoteke()
{
    if(aktivna != NULL)
        fclose(aktivna);

    printf("\nUnesite ime aktivne datoteke: ");
    gets(ime_aktivne);

    if((aktivna = fopen(ime_aktivne, "r+b")) == NULL)
        printf("Datoteke %s ne postoji!\n", ime_aktivne);

    else
        printf("Datoteka %s je aktivna.\n", ime_aktivne);
}

void prikaz_naziva_aktivne_datoteke()
{
    if(aktivna == NULL)
        printf("Aktivna datoteka nije otvorena!\n");

    else
        printf("Datoteka %s je trenutno aktivna datoteka.\n", ime_aktivne);
}

void upis_novog_sloga_u_pomocnu_serijsku_datoteku()
{
    if(serijska == NULL)
        serijska = fopen(ime_serijske, "a+b");

    printf("\nUnesite podatke >> \n\n");

    do
    {
        printf("Unesite evidencioni broj (tacno 7 cifara): ");
        scanf("%ld", &slog.evidencioni_broj);
        getchar();  //zbog gets ne brisi
    } while(slog.evidencioni_broj<1000000 || slog.evidencioni_broj>10000000);

    do
    {
        printf("Unesite ime i prezime spasenog (max 60 karaktera): ");
        gets(slog.ime_i_prezime_spasenog);
    } while((strlen(slog.ime_i_prezime_spasenog))<0 || (strlen(slog.ime_i_prezime_spasenog))>60);


    printf("Unesite datum spasavanja>>\n");

    do
    {
        printf("  Unesite dan: ");
        scanf("%d", &slog.datum.dan);
    } while(slog.datum.dan<1 || slog.datum.dan>31);

    do
    {
        printf("  Unesite mjesec: ");
        scanf("%d", &slog.datum.mjesec);
    } while(slog.datum.mjesec<1 || slog.datum.mjesec>12);

    do
    {
        printf("  Unesite godinu: ");
        scanf("%d", &slog.datum.godina);
    } while(slog.datum.godina >2016);

    printf("Unesite vrijeme spsavanja>>\n");

    do
    {
        printf("  Unesite sat: ");
        scanf("%d", &slog.vrijeme.sat);
    } while(slog.vrijeme.sat<0 || slog.vrijeme.sat>24);

    do
    {
        printf("  Unesite minut: ");
        scanf("%d", &slog.vrijeme.minut);
    } while(slog.vrijeme.minut<0 || slog.vrijeme.minut>59);

    do
    {
        printf("  Unesite sekund: ");
        scanf("%d", &slog.vrijeme.sekund);
        getchar();
    } while(slog.vrijeme.sekund<0 || slog.vrijeme.sekund>59);

    do
    {
        printf("Unesite oznaku spasioca (tacno 5 karaktera): ");
        gets(slog.oznaka_spasioca);
    } while((strlen(slog.oznaka_spasioca))!=5);

    do
    {
        printf("Unesite trajanje spasavanja (do 4300 min): ");
        scanf("%d", &slog.trajanje_spasavanja);
        getchar();
    } while(slog.trajanje_spasavanja<0 || slog.trajanje_spasavanja>4300);

    slog.status = 1;    //postavljanje statusa sloga na 1 znaci da lokacija sad sadrzi aktuelni slog

    fwrite(&slog, sizeof(Plaza), 1, serijska);  //upis jednog sloga u serijsku datoteku

    fclose(serijska);
    serijska = NULL;

    printf("\nSlog upisan u pomocnu serijsku datoteku.\n");
}

void linearno_trazenje(FILE* aktivna, long int a, int* ind, int* ind1, int*r, int* q, Baket* baket)
{
    //a - kljuc
    *ind = 99; //ind - indikator uspjesnosti trazenja
    *ind1 = 0; //ind1 - idnikator postojanja slobodnih lokacija
    int pocetni;

    *r = 1 + a % B; //transformacija kljuca u adresu
    pocetni = *r;

    while(*ind==99)
    {
        fseek(aktivna, (*r-1)*sizeof(Baket), SEEK_SET);
        fread(baket, sizeof(Baket), 1, aktivna);    //citanje jednog baketa iz aktivne

        *q = 1;

        while((*q<=b) && (*ind==99))  //prolazim kroz sve slogove unutar baketa
        {
            if(a == baket->slog[*q-1].evidencioni_broj) //provjera da li je kljuc jednak kljucu unutar sloga
                *ind = 0;   //uspjesno trazenje

            else
            {   //if(baket->slog[*q-1].evidencioni_broj == '*')
                if(baket->slog[*q-1].status == 0 || baket->slog[*q-1].status ==9)
                    *ind = 1;   //neuspjesno trazenje

                else
                    *q+=1;
            }

        }

        if(*q>b)    //ako je doslo do prekoracenja prelazi u sledeci baket
        {
            *r = *r % B + 1;  //k //transformacija

            if(*r == pocetni)
            {
                *ind = 1;   //neuspjesno trazenje
                *ind1 = 1;  //nepostojanje slobodnih lokacija
            }

        }

    }

}

void formiranje_aktivne_datoteke()
{
    int status;
    //ind - indikator uspjesnosti trazenja
    //ind1 - indikator postojanja slobodnih lokacija
    int ind, ind1, r, q;

    if(aktivna == NULL)
    {
        printf("Nije otvorena aktivna datoteka.\n");
        return;
    }

    if(serijska == NULL)
        serijska = fopen(ime_serijske, "a+b");

    //formiranje_prazne_datoteke();
    fseek(serijska, 0, SEEK_SET);
    fread(&slog, sizeof(Plaza), 1, serijska);
    status = feof(serijska);


    while(status == 0)  //dok ne dodjem do kraja serijske
    {
        //ind - indikakator uspjesnosti trazenja, ind1 - indikator postojanja slobodnih lokacija
        linearno_trazenje(aktivna, slog.evidencioni_broj, &ind, &ind1, &r, &q, &baket);

        //0 - uspjesno trazenje
        //1 - neuspjesno trazenje

        //ind = 1 //indikator neuspjesnog trazenja
        //ind1 = 0 //indikator postojanja slovodnih lokacija

        if((ind==1) && (ind1==0) && baket.slog[q-1].status == 0)
        {
            baket.slog[q-1] = slog; //postavljanje sloga u baket
            fseek(aktivna, (r-1)*sizeof(Baket), SEEK_SET);  //pozicioniranje u aktivnoj od pocetka pomjereno za lokacija (r-1)*sizeof(baket)
            fwrite(&baket, sizeof(Baket), 1, aktivna); //upisivanje jednog baketa u aktivnu datoteku
        }

        else
            if(ind1==1) //nedostatak slobodnuh lokacija
                status = 1;

        fread(&slog, sizeof(Plaza), 1, serijska);   //citanje jednog sloga iz serijske
        status=feof(serijska);

    }

    printf("Aktivna datoteka je kreirana.\n");

    fclose(serijska);
    fclose(aktivna);
    aktivna=NULL;


    serijska = fopen(ime_serijske, "w+b");  //otvaram ponovo serijsku u rezimu pisanja da bi se obrisao predhodni sadrzaj
    aktivna=fopen(ime_aktivne, "r+b");  //otvaram aktivnu u rezimu citanja da bi mogao da prikazem slogovee

}

void prikaz_svih_slogova_aktivne_datoteke()
{
    int r, q;

    if(aktivna == NULL)
    {
        printf("Nije otvorena aktivna datoteka!\n");
        return;
    }

    r=1;

    while(r<=B) //prolazim kroz sve bakete unutar datoteke
    {
        fseek(aktivna, (r-1)*sizeof(Baket), SEEK_SET);
        fread(&baket, sizeof(Baket), 1, aktivna);

        q=1;

        while(q<=b) //prolazim kroz slogove unutar baketa
        {
            if(baket.slog[q-1].status > 0)
            {
                printf("\n=========================================\n");
                printf("Adresa baketa: %d\n", r);
                printf("Redni broj sloga: %d\n", q);
                printf("Evidencioni broj: %ld\n", baket.slog[q-1].evidencioni_broj);
                printf("Ime i prezime spasenog: %s\n", baket.slog[q-1].ime_i_prezime_spasenog);
                printf("Datum spasavanja: %d.%d.%d.\n", baket.slog[q-1].datum.dan, baket.slog[q-1].datum.mjesec, baket.slog[q-1].datum.godina);
                printf("Vrijeme spasavanja: %d:%d:%d\n", baket.slog[q-1].vrijeme.sat, baket.slog[q-1].vrijeme.minut, baket.slog[q-1].vrijeme.sekund);
                printf("Oznaka spasioca: %s\n", baket.slog[q-1].oznaka_spasioca);
                printf("Trajanje spasavanja: %d min.\n", baket.slog[q-1].trajanje_spasavanja);
                printf("=========================================\n");

                if(baket.slog[q-1].status==9)
                    printf("LOGICKI OBRISAN SLOG!\n");
            }

            q++;
        }

        r++;
    }
}

void logicko_brisanje_aktuelnog_sloga_iz_aktivne_datoteke()
{
    int r, q, ind, ind1;
    long int kljuc;

    if(aktivna == NULL)
    {
        printf("Nije otvorena aktivna datoteka!\n");
        return;
    }

     do
    {
        printf("Unesite kljuc (tacno 7 cifara): ");
        scanf("%ld", &kljuc);
    } while(kljuc<1000000 || kljuc>10000000);

    linearno_trazenje(aktivna, kljuc, &ind, &ind1, &r, &q, &baket);

    //ind == 0 uspjesno trazenje
    //ind == 1 neuspjesno trazenje

    if(ind == 0)    //uspjesno trazenje
    {
        if(baket.slog[q-1].status == 1) //ako je slog aktuealn
        {
            baket.slog[q-1].status = 9; //mjenjam status sloga
            fseek(aktivna, (r-1)*sizeof(Baket), SEEK_SET);
            fwrite(&baket, sizeof(Baket), 1, aktivna);  //upisujem slog sa izmjenjenim stausom

            printf("Uspjesno brisanje.\n");
        }

        else
            printf("Slog sa kljucem %ld je vec logicki obrisan.\n", kljuc);

    }

    else
        printf("Neuspjesno trazenje...\n");

}

void promjena_vrijednosti_obiljezja_datum_i_vrijeme_spasavana()
{
    int r, q, ind, ind1;
    long int kljuc;

    if(aktivna == NULL)
    {
        printf("Nije otvorena aktivna datoteka!\n");
        return;
    }

    do
    {
        printf("\nUnesite kljuc (tacno 7 cifara): ");
        scanf("%ld", &kljuc);
    } while(kljuc<1000000 || kljuc>10000000);

    linearno_trazenje(aktivna, kljuc, &ind, &ind1, &r, &q, &baket);

    if(ind == 0)    //ako je uspjesno trazenje
    {
        if(baket.slog[q-1].status == 1)   //provjeravam da li je na toj lokaciji aktuelan slog
        {
            printf("Unesite datum >>\n");

            do
            {
                printf("  Unesite dan: ");
                scanf("%d", &slog.datum.dan);
            } while(slog.datum.dan<1 || slog.datum.dan>31);


            do
            {
                printf("  Unesite mjesec: ");
                scanf("%d", &slog.datum.mjesec);
            } while(slog.datum.mjesec<1 || slog.datum.mjesec>12);

            do
            {
                printf("  Unesite godinu: ");
                scanf("%d", &slog.datum.godina);
            } while(slog.datum.godina>2016);



            printf("Unesite vrijeme >>\n");

            do
            {
                printf("  Unesite sat: ");
                scanf("%d", &slog.vrijeme.sat);
            } while(slog.vrijeme.sat<0 || slog.vrijeme.sat>24);

            do
            {
                printf("  Unesite minut: ");
                scanf("%d", &slog.vrijeme.minut);
            } while(slog.vrijeme.minut<0 || slog.vrijeme.minut>59);

            do
            {
                printf("  Unesite sekund: ");
                scanf("%d", &slog.vrijeme.sekund);
            } while(slog.vrijeme.sekund<0 || slog.vrijeme.sekund>59);

            baket.slog[q-1].datum.dan = slog.datum.dan;
            baket.slog[q-1].datum.mjesec = slog.datum.mjesec;
            baket.slog[q-1].datum.godina = slog.datum.godina;

            baket.slog[q-1].vrijeme.sat = slog.vrijeme.sat;
            baket.slog[q-1].vrijeme.minut = slog.vrijeme.minut;
            baket.slog[q-1].vrijeme.sekund = slog.vrijeme.sekund;

            fseek(aktivna, (r-1)*sizeof(Baket), SEEK_SET);
            fwrite(&baket, sizeof(Baket), 1, aktivna);  //upisujem slgo sa izmjenjenim obiljezjima

            printf("\nIzvrsena promjena obiljezja datum i vrijeme.\n");
        }

        else
            printf("Slog je vec logicki obrisan!\n");

    }

    else
        printf("Neuspjesno trazenje...\n");

}


